"""Service failure regression tests; never touches host SSH configuration."""
import json
import importlib.util
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('setup', pathlib.Path(__file__).parents[1] / 'lib/setup.py')
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)

class RecoveryTests(unittest.TestCase):
    def test_sudo_policy_failure_removes_grant_and_restores_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            manifest = root/'manifest.json'; manifest.write_text('{}')
            policy = root/'sudoers'
            with patch.object(setup, 'STATE', root), patch.object(setup, 'MANIFEST', manifest), patch.object(setup, 'SUDOERS', policy), patch.object(setup.shutil, 'which', return_value='/fixture/tool'), patch.object(setup, 'run', side_effect=[None, None, None, RuntimeError('policy rejected')]):
                with self.assertRaisesRegex(RuntimeError, 'policy rejected'):
                    setup.enable_sudo()
            self.assertFalse(policy.exists())
            self.assertEqual(manifest.read_text(), '{}')

    def test_collision_recovery_rejects_modified_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            config, backup = root/'config', root/'backup'
            config.write_text('operator edits'); backup.write_text('original')
            (root/'recovery-required').write_text('Could not stop agent listener: failure')
            manifest = root/'manifest.json'
            manifest.write_text(json.dumps({str(config): {'existed': True, 'backup': str(backup)}}))
            with patch.object(setup, 'STATE', root), patch.object(setup, 'MANIFEST', manifest), patch.object(setup, 'run') as run:
                with self.assertRaisesRegex(RuntimeError, 'not restored'):
                    setup.recover_service_collision()
                run.assert_not_called()
            self.assertTrue(manifest.exists())
            self.assertEqual(config.read_text(), 'operator edits')

    def test_reload_failure_includes_status_and_journal(self):
        results = [subprocess.CompletedProcess([], 1, '', 'reload failed'),
                   subprocess.CompletedProcess([], 1, '', ''),
                   subprocess.CompletedProcess([], 3, 'ExecReload failed', ''),
                   subprocess.CompletedProcess([], 0, 'specific SSH error', '')]
        with patch.object(setup.subprocess, 'run', side_effect=results) as command:
            with self.assertRaisesRegex(RuntimeError, 'specific SSH error'):
                setup.reload_systemd('ssh.service')
            self.assertEqual(command.call_count, 4)

    def test_failed_daemon_is_started_and_checked(self):
        results = [subprocess.CompletedProcess([], code, '', '') for code in (1, 0, 0, 0)]
        with patch.object(setup.subprocess, 'run', side_effect=results) as command:
            setup.reload_systemd('ssh.service')
            self.assertEqual(command.call_args_list[2].args[0], ['systemctl', 'start', 'ssh.service'])
            self.assertEqual(command.call_args_list[3].args[0], ['systemctl', 'is-active', '--quiet', 'ssh.service'])

    def test_failed_recovery_is_not_reported_as_success(self):
        results = [subprocess.CompletedProcess([], code, '', '') for code in (1, 0, 1, 3, 0)]
        with patch.object(setup.subprocess, 'run', side_effect=results):
            with self.assertRaisesRegex(RuntimeError, 'Reload of ssh.service failed'):
                setup.reload_systemd('ssh.service')

    def test_success_does_not_collect_logs(self):
        with patch.object(setup.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '', '')) as command:
            setup.reload_systemd('ssh.service')
            self.assertEqual(command.call_count, 1)

    def test_rollback_restores_before_reload_and_expires_agent(self):
        for recovery_fails in (False, True):
            with self.subTest(recovery_fails=recovery_fails), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                config, backup, manifest = root/'config', root/'backup', root/'manifest.json'
                config.write_text('changed'); backup.write_text('original'); manifest.write_text('{}')
                def reload():
                    self.assertEqual(config.read_text(), 'original')
                    if recovery_fails: raise RuntimeError('recovery reload failed')
                with patch.object(setup, 'STATE', root), patch.object(setup, 'MANIFEST', manifest), patch.object(setup, 'run') as run, patch.object(setup, 'service') as service, patch.object(setup, 'reload_original', side_effect=reload):
                    setup.rollback({str(config): {'existed': True, 'backup': str(backup)}}, True)
                    run.assert_called_once_with('usermod', '--expiredate', '1', 'agent')
                    service.assert_called_once_with('stop')
                self.assertEqual(manifest.exists(), recovery_fails)
                self.assertEqual((root/'recovery-required').exists(), recovery_fails)

if __name__ == '__main__': unittest.main()
