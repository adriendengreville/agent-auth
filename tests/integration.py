"""Destructive integration test: run ONLY in a disposable Linux container as root."""
import json, base64, hashlib, hmac, os, pathlib, re, socket, struct, subprocess, sys, time
import pexpect, paramiko
P=pathlib.Path
if os.environ.get('AGENT_AUTH_DISPOSABLE')!='yes': raise SystemExit('Requires AGENT_AUTH_DISPOSABLE=yes')
def run(*args,**kw): return subprocess.run(args,check=True,**kw)
def otp(seed):
    d=hmac.new(base64.b32decode(seed),struct.pack('>Q',int(time.time())//30),hashlib.sha1).digest(); n=d[-1]&15
    return f'{(struct.unpack(">I",d[n:n+4])[0]&0x7fffffff)%1000000:06d}'
run('ssh-keygen','-A'); P('/run/sshd').mkdir(exist_ok=True)
run('useradd','-m','-s','/bin/sh','owner'); run('chpasswd',input=b'owner:fixture-owner-password\n')
key=paramiko.RSAKey.generate(2048)
p=P('/home/owner/.ssh');p.mkdir(mode=0o700);(p/'authorized_keys').write_text(key.get_name()+' '+key.get_base64()+'\n');os.chmod(p/'authorized_keys',0o600)
run('chown','-R','owner:owner',str(p))
P('/etc/ssh/sshd_config').write_text('Port 2223\nUsePAM yes\nPasswordAuthentication yes\nPubkeyAuthentication yes\nPidFile /run/sshd.pid\n')
sshd='/usr/sbin/sshd.pam' if P('/usr/sbin/sshd.pam').exists() else '/usr/sbin/sshd'
if os.environ.get('AGENT_AUTH_SYSTEMD') == 'yes':
    run('systemctl', 'stop', 'ssh.socket', 'ssh.service')
    # Regenerate socket-activation settings for the fixture's nonstandard port.
    run('systemctl', 'daemon-reload')
    run('systemctl', 'start', 'ssh.service')
    for attempt in range(50):
        try:
            with socket.create_connection(('127.0.0.1', 2223), timeout=2) as connection:
                assert connection.recv(256).startswith(b'SSH-2.0-')
            break
        except OSError:
            if attempt == 49:
                run('journalctl', '-u', 'ssh.service', '-n', '30', '--no-pager')
                raise
            time.sleep(0.1)
else:
    run(sshd)
original=P('/etc/pam.d/sshd').read_bytes()
if os.environ.get('AGENT_AUTH_SYSTEMD') == 'yes':
    # Reproduce the prior version's restored files plus retained recovery marker.
    state=P('/var/lib/agent-auth'); state.mkdir(mode=0o700, exist_ok=True)
    backup=state/'backup-test'; backup.write_bytes(P('/etc/ssh/sshd_config').read_bytes())
    (state/'manifest.json').write_text(json.dumps({
        '/etc/ssh/sshd_config': {'existed': True, 'backup': str(backup)},
        '/etc/systemd/system/agent-auth.service': {'existed': False},
        '/etc/init.d/agent-auth': {'existed': False},
    }))
    (state/'recovery-required').write_text("Could not stop agent listener: Command '('systemctl', 'disable', '--now', 'agent-auth.service')' returned non-zero exit status 1.")

install_args = ['/src/configure'] + (['--sudoer'] if os.environ.get('AGENT_AUTH_SYSTEMD') == 'yes' else [])
child=pexpect.spawn('/bin/sh',install_args,timeout=300,encoding='utf-8')
child.expect(r'Manual generation key: ([A-Z2-7]+)');seed=child.match.group(1)
child.expect('Enter the current code from your authenticator:');child.sendline(otp(seed));child.expect(pexpect.EOF);child.close()
if child.exitstatus!=0: raise AssertionError('configure failed: '+child.before)
if os.environ.get('AGENT_AUTH_SYSTEMD') == 'yes':
    assert not P('/etc/init.d/agent-auth').exists(), 'OpenRC script must not be installed on systemd'
    run('systemctl', 'is-enabled', '--quiet', 'agent-auth.service')
    run('systemctl', 'is-active', '--quiet', 'agent-auth.service')
# Even an explicitly installed key must not bypass OTP.
p=P('/home/agent/.ssh');p.mkdir(mode=0o700);(p/'authorized_keys').write_text(key.get_name()+' '+key.get_base64()+'\n');os.chmod(p/'authorized_keys',0o600)
run('chown','-R','agent:agent',str(p))
def conn(user,port,method,value):
    t=paramiko.Transport(('127.0.0.1',port));t.start_client(timeout=10)
    try:
        if method=='otp':t.auth_interactive(user,lambda title,instructions,prompts:[value]*len(prompts))
        elif method=='key':t.auth_publickey(user,value)
        else:t.auth_password(user,value,fallback=False)
        c=t.open_session();c.exec_command('id -un');result=c.makefile().read().decode().strip();return result
    finally:t.close()
assert conn('owner',2223,'key',key)=='owner';print('PASS administrator key preserved')
assert conn('owner',2223,'password','fixture-owner-password')=='owner';print('PASS administrator password preserved')
for user,port,method,value in [('agent',2223,'otp',otp(seed)),('agent',2222,'key',key),('agent',2222,'password','anything'),('owner',2222,'key',key),('agent',2222,'otp','000000')]:
    try:conn(user,port,method,value)
    except (paramiko.AuthenticationException,paramiko.SSHException):pass
    else:raise AssertionError('Unexpected authentication success '+str((user,port,method)))
print('PASS alternate login paths and wrong OTP rejected')
# Wrong attempt and previous test connections may trigger rate limiting.
time.sleep(31)
code=otp(seed);assert conn('agent',2222,'otp',code)=='agent';print('PASS valid OTP opens agent session')
try:conn('agent',2222,'otp',code)
except paramiko.AuthenticationException:pass
else:raise AssertionError('Replay accepted')
print('PASS OTP replay rejected')
run('su','-s','/bin/sh','agent','-c','test ! -r /etc/agent-auth/agent.totp')
print('PASS agent cannot read seed directly')
if os.environ.get('AGENT_AUTH_SYSTEMD') != 'yes':
    assert not P('/etc/sudoers.d/agent-auth').exists()
    run('/src/configure', '--sudoer')
run('python3', '/src/lib/setup.py', '--sudoer')
assert run('su', '-s', '/bin/sh', 'agent', '-c', 'sudo -n id -u', capture_output=True, text=True).stdout.strip() == '0'
assert P('/etc/sudoers.d/agent-auth').stat().st_mode & 0o777 == 0o440
print('PASS opt-in passwordless sudo and idempotent rerun')
run('/src/configure','--uninstall')
assert P('/etc/pam.d/sshd').read_bytes()==original
assert not P('/etc/sudoers.d/agent-auth').exists()
print('PASS uninstall removes managed sudo grant')
time.sleep(2)
assert conn('owner',2223,'key',key)=='owner'
try:conn('agent',2223,'key',key)
except paramiko.AuthenticationException:pass
else:raise AssertionError('Uninstalled agent account still accessible')
print('PASS uninstall restores administrator access and expires agent account')
