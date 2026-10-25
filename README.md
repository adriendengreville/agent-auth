# agent-auth

Human-approved SSH access using a phone-generated TOTP code. The dedicated account
is `agent`. No SSH client key is required. Your existing administrator SSH login
keeps its original authentication and port.

## Install

On the **target Linux container or VM**, as root:

```sh
git clone https://github.com/adriendengreville/agent-auth.git
cd agent-auth
./configure
```

Or run `sudo ./configure`. The entry point is POSIX sh; invoking it with bash,
zsh, dash or BusyBox ash is supported. Python 3 is installed for configuration.

The installer installs OS packages, creates an unprivileged account, displays a
locally rendered QR code and a manual Base32 generation key, and asks you to enter
a current code from your authenticator. Use any TOTP app: SHA1, six digits,
30-second period. Each target has a separate secret. Keep the target clock correct.
The QR and manual key are secrets: enroll directly in your own terminal, not in
an agent session whose output the agent can read. No external QR website is used.

Connect from the agent's laptop:

```sh
ssh -p 2222 agent@TARGET_IP
```

Verify the server host-key fingerprint using your trusted administrator connection.
Provide a fresh code when prompted. A code is rejected after successful use.
Three failed/total login attempts per 30 seconds are rate limited by the OTP module;
its acceptance window allows one time step of clock skew in either direction.

Keep your administrator session open during installation and verify a **new** admin
connection and an agent connection before closing it. Firewall configuration is
left to you; permit the chosen agent port only from your intended network.

## Architecture

A separate OpenSSH daemon listens on port 2222 (`--port NUMBER` changes it). This
allows Alpine's PAM-enabled `sshd.pam` to run alongside its ordinary non-PAM SSH
server, and keeps administrator authentication on its existing listener.

The normal `/etc/ssh/sshd_config` receives `DenyUsers agent`, preventing an alternate
agent login there. The dedicated listener permits only `agent` and only PAM
keyboard-interactive authentication. Password/public-key/host-based authentication
and SSH forwarding are disabled on that listener. Do not run another independently
configured SSH/Dropbear listener permitting this account: that would be a bypass.

`/etc/pam.d/sshd` routes agent authentication to a root-owned OTP file. Other users
run the original auth stack inside a PAM substack. Original account, password and
session stacks are retained. The installer does not change global `common-auth`
or add OTP to sudo/console authentication.

Files:

- `/etc/agent-auth/agent.totp`: root-only seed and rate/replay state.
- `/etc/agent-auth/sshd_config`: isolated listener configuration.
- `/etc/agent-auth/start`: standalone supervisor entry point.
- `/var/lib/agent-auth`: root-only configuration backups and install manifest.
- `/etc/pam.d/agent-auth-original`: original SSH PAM stack.

By default, the `agent` account receives **no sudo rights**. An administrator can grant selected
maintenance operations separately. Unrestricted root can read the seed or bypass
this policy. The account also must not have access to your administrator key or
SSH-agent socket. Forwarding restrictions do not sandbox a general-purpose shell.
OTP expiry does not close an established session or SSH multiplexed connection.

## Platforms and compatibility

| Environment | Path |
|---|---|
| Debian / Ubuntu | apt installs OpenSSH, PAM OTP, QR tools, Python |
| Alpine / BusyBox ash | apk installs `openssh-server-pam`; dedicated daemon uses `sshd.pam` |
| Fedora / RHEL family | dnf package adapter (OTP package must be in enabled repositories) |
| openSUSE | zypper package adapter |
| Arch | pacman package adapter |
| Other Linux | Uses already-installed compatible dependencies |

BusyBox is a collection of tools, not a package manager or guarantee that PAM is
available. A minimal appliance with neither packages nor a usable PAM/OpenSSH
runtime needs its underlying Linux image extended first. The installer attempts
native package installation and the Alpine PAM variant; it never substitutes a
password for OTP. Package adapters beyond Debian/Ubuntu/Alpine need platform testing.

systemd and OpenRC service definitions are installed. On an image without a running
init system, the daemon starts directly; configure your supervisor to run
`/etc/agent-auth/start -D` for restart persistence. Use `--no-start` for image builds.
Do not clone an enrolled image to create multiple targets: enroll separately.

## Re-run, recovery and uninstall

Running configure again retains the seed and recognizes an existing installation.
It does not print the secret again. An existing unrelated `agent` account is not
silently adopted.

```sh
./configure --uninstall
```

Uninstall restores backed-up SSH/PAM/service configuration, retaining the account,
packages and private enrollment for deliberate cleanup. The retained agent account
is expired to prevent login through restored administrator SSH configuration. It refuses to overwrite
files changed since installation; inspect the manifest and merge changes manually.
Configuration validation failures restore the files modified in that attempt.
Package installation, host-key creation, and account creation are not rolled back.

Backup the root-only state as sensitive data. Restoring an old snapshot can restore
old OTP replay state; rotate enrollment after a security-sensitive rollback.

## Tests

`tests/integration.py` is destructive and must run only in disposable containers.
It exercises real SSH authentication, including OTP success, OTP replay, invalid
codes, alternate-method rejection, administrator key/password preservation,
seed permissions, and uninstall. Test fixture credentials are generated or used
only inside disposable test containers; enrollment output is not logged.

Example Debian test preparation:

```sh
apt-get update
apt-get install -y python3-paramiko python3-pexpect openssh-server
AGENT_AUTH_DISPOSABLE=yes python3 /src/tests/integration.py
```

Mount this repo at `/src`. See `TESTING.md` for the actual verified matrix.

## License

MIT. This project configures distribution-provided OpenSSH and Google Authenticator
PAM packages, which retain their own licenses.

### SSH service exits during reload

Some distribution OpenSSH builds can exit after SIGHUP with `Cannot bind any
address` (see [Debian #1128329](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1128329)).
If a systemd reload fails and the service is failed, configure starts it again
through systemd and checks that it is active. A service already failed from an
earlier attempt is also started. A running service whose reload fails is not
forcibly restarted. Unresolved errors include service status and recent journal
entries.

On installation failure, the agent account is expired, changed files are restored,
and the original SSH configuration is reapplied. Enrollment is retained. If any
recovery step fails, the installer retains backups and records
`/var/lib/agent-auth/recovery-required`; inspect that file before another attempt.
Keep your current administrator session open until a new login succeeds.

Only the appropriate init service definition is installed: the systemd unit when
systemctl is available, otherwise the OpenRC script when rc-service is available.
Installing both under the same name makes Debian's SysV synchronization reject the
OpenRC script. For the old version's specific failed-cleanup marker, a rerun checks
that every tracked file matches its restored backup (or is absent if newly created),
cleans up service enablement, and reapplies administrator SSH before retrying.
It retains the OTP seed and refuses automatic recovery if files have changed.

### Optional sudo access

Run `./configure --sudoer` as root for unrestricted passwordless sudo. This works
both during first installation and on an already enrolled target without changing
its OTP seed or restarting SSH solely to add sudo. The installer installs `sudo`,
validates the policy with `visudo`, and verifies effective passwordless elevation.
The managed grant is `/etc/sudoers.d/agent-auth` (root-owned, mode 0440).
Repeated `--sudoer` runs are idempotent; ordinary reruns do not revoke the grant.
Uninstall removes the grant it created and refuses to overwrite an edited policy.
Unrelated, manually created sudo grants remain untouched.

```sh
./configure --sudoer
# In an agent SSH session:
sudo -n id
sudo -i
```

This allows root access after the SSH OTP check, with no further approval prompt.
Root can read the OTP seed, alter authentication, and establish persistent access.
If granting sudo fails on a new installation, the SSH installation remains usable;
fix the reported sudo error and rerun `./configure --sudoer`.
