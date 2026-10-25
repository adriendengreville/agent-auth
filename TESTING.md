# Verification

The test runs a real SSH daemon in disposable Linux containers. It creates an
administrator fixture before configuration, enrolls an ephemeral test TOTP through
the interactive installer, and performs SSH authentication with Paramiko.

Verified locally:

- Debian 12 (bookworm), default `/bin/sh` (dash).
- Ubuntu 24.04, default `/bin/sh` (dash).
- Alpine 3.22, BusyBox ash and the distro's `sshd.pam` package.
- POSIX entry-point help under macOS sh, bash, and zsh (installer itself targets Linux).

Test assertions: administrator SSH key and password still work; normal listener
rejects agent; dedicated listener rejects owner, public keys, password auth, and
wrong OTP; valid OTP works; used OTP is rejected; agent cannot read the seed;
uninstall restores the original PAM file and administrator connectivity.

GitHub Actions repeats the suite for Debian 12, Ubuntu 24.04, and Alpine 3.22.
Fedora/RHEL, openSUSE and Arch package adapters are not yet integration-tested.
Systemd/OpenRC unit definitions are supplied; local Docker tests exercise the
standalone-daemon path, not a real boot under those init systems.

Service failure regression tests (`python3 -m unittest discover -s tests -p
 'test_*.py'`) simulate systemctl responses: successful reload, daemon exit during
reload followed by successful start, failed recovery, and rollback restoration.
These tests do not constitute a live systemd test. The CI authentication matrix
also includes Debian 13 (trixie); that job still uses the standalone daemon path.
