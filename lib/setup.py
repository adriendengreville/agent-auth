#!/usr/bin/env python3
"""Root-only installer; no secrets or OTPs leave the target."""
import argparse, base64, hashlib, hmac, json, os, pathlib, secrets, shutil, socket, struct, subprocess, sys, time, urllib.parse
P = pathlib.Path
STATE = P('/var/lib/agent-auth')
ETC = P('/etc/agent-auth')
SSH = P('/etc/ssh/sshd_config')
PAM = P('/etc/pam.d/sshd')
MANIFEST = STATE / 'manifest.json'
def run(*args, **kw):
    return subprocess.run(args, check=True, **kw)
def write(path, text, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.agent-auth-tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, 'w') as f: f.write(text)
        os.chmod(tmp, mode); os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)
def otp(seed, counter):
    digest = hmac.new(base64.b32decode(seed), struct.pack('>Q', counter), hashlib.sha1).digest()
    n = digest[-1] & 15
    return f'{(struct.unpack(">I", digest[n:n+4])[0] & 0x7fffffff) % 1000000:06d}'
def enroll():
    path = ETC / 'agent.totp'
    if path.exists():
        print('Existing OTP enrollment retained. No seed is printed on reruns.'); return
    if not sys.stdin.isatty(): raise RuntimeError('Enrollment needs an interactive terminal. Run ./configure directly.')
    seed = base64.b32encode(secrets.token_bytes(20)).decode()
    label = 'agent@' + socket.gethostname()
    uri = 'otpauth://totp/' + urllib.parse.quote('agent-auth:' + label, safe='') + '?' + urllib.parse.urlencode({'secret': seed, 'issuer': 'agent-auth', 'algorithm': 'SHA1', 'digits': 6, 'period': 30})
    print('\nScan this QR locally; do not upload it to an online QR generator.')
    if shutil.which('qrencode'):
        run('qrencode', '-t', 'ANSIUTF8', input=uri, text=True)
    else:
        print('qrencode executable unavailable; use the manual setup key below.')
    print(f'Account: {label}\nManual generation key: {seed}\nType: time-based, SHA1, 6 digits, 30 seconds')
    import getpass
    for _ in range(5):
        code = getpass.getpass('Enter the current code from your authenticator: ').strip()
        now = int(time.time()) // 30
        if any(hmac.compare_digest(code, otp(seed, now+d)) for d in (-1,0,1)):
            write(path, seed + '\n" TOTP_AUTH\n" DISALLOW_REUSE\n" WINDOW_SIZE 3\n" RATE_LIMIT 3 30\n')
            print('Enrollment verified. Seed saved root-only.'); return
        print('Incorrect code. Check the phone and target clocks.')
    raise RuntimeError('Enrollment not confirmed; authentication configuration was not changed.')
def service(action):
    if shutil.which('systemctl') and P('/run/systemd/system').exists():
        if action == 'start':
            run('systemctl', 'daemon-reload'); run('systemctl', 'enable', '--now', 'agent-auth.service')
        else: run('systemctl', 'disable', '--now', 'agent-auth.service')
    elif shutil.which('rc-service') and P('/run/openrc').exists():
        if action == 'start': run('rc-update', 'add', 'agent-auth', 'default')
        run('rc-service', 'agent-auth', action)
        if action == 'stop': run('rc-update', 'del', 'agent-auth', 'default')
    else:
        if action == 'start':
            print('No running systemd/OpenRC detected. Starting sshd directly; configure your supervisor for reboot persistence.')
            run(str(ETC / 'start'))
        else:
            pid = P('/run/agent-auth.pid')
            if pid.exists():
                # Confirm PID belongs to our daemon before signalling it.
                n = int(pid.read_text()); cmd = P(f'/proc/{n}/cmdline').read_bytes()
                if b'/etc/agent-auth/sshd_config' not in cmd: raise RuntimeError('PID is not agent-auth; refusing to signal it')
                os.kill(n, 15)
def reload_original():
    if shutil.which('systemctl') and P('/run/systemd/system').exists():
        for unit in ('ssh.service', 'sshd.service'):
            if subprocess.run(['systemctl','is-active','--quiet',unit]).returncode == 0:
                run('systemctl','reload',unit); return
    elif shutil.which('rc-service') and P('/run/openrc').exists():
        if subprocess.run(['rc-service','sshd','status'], stdout=subprocess.DEVNULL).returncode == 0:
            run('rc-service','sshd','reload'); return
    else:
        # Common standalone sshd PID files. Never kill an unrelated process.
        for name in ('/run/sshd.pid','/var/run/sshd.pid'):
            p=P(name)
            if p.exists():
                n=int(p.read_text()); cmd=P(f'/proc/{n}/cmdline').read_bytes()
                if b'sshd' in cmd and b'agent-auth' not in cmd: os.kill(n,1)
                return
        print('No original SSH daemon found running; its agent restriction applies on next startup.')
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--port',type=int,default=2222); ap.add_argument('--no-start',action='store_true'); ap.add_argument('--uninstall',action='store_true'); a=ap.parse_args()
    if os.geteuid()!=0: raise RuntimeError('Root required')
    if not 1<=a.port<=65535 or a.port==22: raise RuntimeError('Choose an unused port other than 22')
    STATE.mkdir(mode=0o700,parents=True,exist_ok=True); os.chmod(STATE,0o700)
    ETC.mkdir(mode=0o700,parents=True,exist_ok=True); os.chmod(ETC,0o700)
    if a.uninstall:
        if not MANIFEST.exists(): raise RuntimeError('No installation to uninstall')
        m=json.loads(MANIFEST.read_text())
        for f,d in m.items():
            if P(f).exists() and hashlib.sha256(P(f).read_bytes()).hexdigest()!=d['installed']:
                raise RuntimeError(f'{f} changed after installation. Merge with {d["backup"]} manually before uninstalling.')
        service('stop')
        for f,d in m.items():
            if d['existed']: shutil.copy2(d['backup'], f)
            else: P(f).unlink(missing_ok=True)
        MANIFEST.unlink(); reload_original()
        print('Configuration restored. Agent account, installed packages and private seed retained.'); return
    if MANIFEST.exists():
        print('Already installed. Use the existing enrollment; uninstall before reconfiguration.'); return
    sshd=shutil.which('sshd.pam') or shutil.which('sshd')
    if not sshd: raise RuntimeError('PAM-enabled sshd not installed')
    for mod in ('pam_google_authenticator.so','pam_succeed_if.so'):
        if not any(list(P(root).glob('**/'+mod)) for root in ('/lib','/usr/lib','/lib64','/usr/lib64') if P(root).exists()):
            raise RuntimeError(f'Missing {mod}; enable your distribution repository containing this PAM module.')
    run('ssh-keygen','-A',stdout=subprocess.DEVNULL)
    P('/run/sshd').mkdir(mode=0o755,exist_ok=True)
    # Probe PAM support before touching accounts or SSH policy.
    probe=run(sshd,'-T','-o','UsePAM=yes',stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    if 'usepam yes' not in probe.stdout: raise RuntimeError('This OpenSSH build lacks PAM; install the distribution PAM variant')
    with socket.socket() as s: s.bind(('0.0.0.0',a.port))
    import pwd
    try:
        pwd.getpwnam('agent')
        if not (STATE/'account-created').exists(): raise RuntimeError('An unmanaged agent account already exists; refusing to take it over')
        exists=True
    except KeyError: exists=False
    enroll()
    if not exists:
        run('useradd','-m','-s','/bin/sh','agent')
        write(STATE/'account-created','agent\n')
        # Random unknown password avoids locked-account PAM checks; SSH disallows password auth.
        run('chpasswd',input='agent:'+secrets.token_urlsafe(48)+'\n',text=True,stdout=subprocess.DEVNULL)
    run('ssh-keygen','-A',stdout=subprocess.DEVNULL)
    P('/run/sshd').mkdir(mode=0o755,exist_ok=True)
    files={}
    def install(path,text,mode=0o600):
        backup=STATE/('backup-'+str(len(files)))
        existed=path.exists()
        if existed: shutil.copy2(path,backup)
        files[str(path)]={'backup':str(backup),'existed':existed,'installed':hashlib.sha256(text.encode()).hexdigest()}
        write(path,text,mode)
    original=PAM.read_text() if PAM.exists() else 'auth required pam_unix.so\naccount required pam_unix.so\nsession required pam_unix.so\n'
    try:
        install(P('/etc/pam.d/agent-auth-original'), original,0o644)
        install(P('/etc/pam.d/agent-auth-otp'), 'auth requisite pam_google_authenticator.so secret=/etc/agent-auth/agent.totp user=root\nauth required pam_permit.so\n',0o644)
        install(PAM, '''# Managed by agent-auth; original stack preserved separately.
auth [success=1 default=ignore] pam_succeed_if.so user = agent
auth substack agent-auth-original
auth [success=1 default=ignore] pam_succeed_if.so user != agent
auth substack agent-auth-otp
account include agent-auth-original
session include agent-auth-original
password include agent-auth-original
''',0o644)
        install(SSH,'# agent-auth: dedicated listener only\nDenyUsers agent\n'+(SSH.read_text() if SSH.exists() else ''),0o600)
        install(ETC/'sshd_config',f'''Port {a.port}
PidFile /run/agent-auth.pid
UsePAM yes
AllowUsers agent
PermitRootLogin no
AuthenticationMethods keyboard-interactive:pam
KbdInteractiveAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
PubkeyAuthentication no
HostbasedAuthentication no
DisableForwarding yes
PermitUserRC no
MaxAuthTries 3
LoginGraceTime 120
LogLevel VERBOSE
''')
        install(ETC/'start',f'#!/bin/sh\nmkdir -p /run/sshd\nexec {sshd} -f /etc/agent-auth/sshd_config "$@"\n',0o700)
        install(P('/etc/systemd/system/agent-auth.service'),'''[Unit]
Description=Agent OTP SSH endpoint
After=network.target
[Service]
Type=simple
ExecStart=/etc/agent-auth/start -D
Restart=on-failure
[Install]
WantedBy=multi-user.target
''',0o644)
        install(P('/etc/init.d/agent-auth'),f'''#!/sbin/openrc-run
name="Agent OTP SSH"
command="{sshd}"
command_args="-f /etc/agent-auth/sshd_config"
pidfile="/run/agent-auth.pid"
depend() {{ need net; }}
start_pre() {{ checkpath --directory --mode 0755 /run/sshd; }}
''',0o755)
        run(sshd,'-t','-f',str(ETC/'sshd_config'))
        normal=shutil.which('sshd') or sshd
        run(normal,'-t','-f',str(SSH))
        effective=run(sshd,'-T','-f',str(ETC/'sshd_config'),stdout=subprocess.PIPE,text=True).stdout
        for value in ('authenticationmethods keyboard-interactive:pam','pubkeyauthentication no','passwordauthentication no','allowusers agent'):
            if value not in effective: raise RuntimeError('Unexpected effective SSH configuration: '+value)
        write(MANIFEST,json.dumps(files,indent=2))
        reload_original()
        if not a.no_start: service('start')
    except BaseException:
        for path,d in reversed(list(files.items())):
            if d['existed']: shutil.copy2(d['backup'],path)
            else: P(path).unlink(missing_ok=True)
        MANIFEST.unlink(missing_ok=True)
        print('Configuration rolled back. Enrollment and account retained for retry.',file=sys.stderr)
        raise
    print(f'\nConfigured. Connect: ssh -p {a.port} agent@<target-ip>\nAgent has no sudo privileges. Existing administrator SSH remains on its original port.')
    print('Keep your administrator session open and verify a NEW administrator login and an agent OTP login.')
if __name__=='__main__':
    try: main()
    except (RuntimeError,subprocess.CalledProcessError,OSError) as e:
        print('ERROR: '+str(e),file=sys.stderr); sys.exit(1)
