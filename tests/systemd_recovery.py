"""Run only on a disposable Linux CI runner with systemd and OpenSSH installed."""
import importlib.util
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time

if os.environ.get('AGENT_AUTH_DISPOSABLE') != 'yes':
    raise SystemExit('Requires AGENT_AUTH_DISPOSABLE=yes')
spec = importlib.util.spec_from_file_location('setup', Path(__file__).parents[1] / 'lib/setup.py')
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)
unit = 'agent-auth-recovery-test.service'
unit_file = Path('/etc/systemd/system') / unit
if unit_file.exists(): raise SystemExit('Refusing to overwrite existing unit')
def run(*args): return subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()
def banner():
    # Type=simple reports started before sshd has bound its socket.
    for attempt in range(50):
        try:
            with socket.create_connection(('127.0.0.1', 22991), timeout=5) as connection:
                assert connection.recv(256).startswith(b'SSH-2.0-')
            return
        except ConnectionRefusedError:
            if attempt == 49: raise
            time.sleep(0.1)
with tempfile.TemporaryDirectory(prefix='agent-auth-test-') as directory:
    root = Path(directory)
    run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(root/'host_key'))
    (root/'sshd_config').write_text(f'Port 22991\nListenAddress 127.0.0.1\nHostKey {root}/host_key\nPidFile {root}/sshd.pid\nPasswordAuthentication no\n')
    Path('/run/sshd').mkdir(mode=0o755, exist_ok=True)
    # Deliberately kill only this test listener during reload to reproduce a failed
    # systemd job. Recovery must launch a fresh sshd through systemd.
    unit_file.write_text(f'''[Unit]
Description=Disposable agent-auth recovery test
[Service]
Type=simple
ExecStart={shutil.which('sshd')} -D -f {root}/sshd_config
ExecReload=/bin/sh -c 'kill -KILL "$MAINPID"; exit 1'
KillMode=process
''')
    try:
        run('systemctl', 'daemon-reload')
        run('systemctl', 'start', unit)
        banner()
        before = run('systemctl', 'show', '-p', 'MainPID', '--value', unit)
        setup.reload_systemd(unit)
        after = run('systemctl', 'show', '-p', 'MainPID', '--value', unit)
        assert before != after and after != '0'
        banner()
        print('PASS real systemd reload failure recovers a fresh SSH listener')
    finally:
        subprocess.run(['systemctl', 'stop', unit], check=False)
        unit_file.unlink()
        run('systemctl', 'daemon-reload')
