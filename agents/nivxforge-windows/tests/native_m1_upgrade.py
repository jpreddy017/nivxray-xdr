"""Windows-only, isolated SCM/TLS fixture. No production endpoint or secrets.

Runs only on an ephemeral GitHub-hosted runner. A temporary trusted test CA
enables real TLS verification for the LocalSystem service; it is removed finally.
"""
import datetime
import hashlib
import http.server
import ipaddress
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import threading
import time
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import nivxforge_m1 as m1
import nivxforge_m1_upgrade as upgrade


def main():
    if os.name != 'nt' or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise SystemExit('Only run this fixture on an ephemeral GitHub Windows runner')
    host=m1.WindowsHost(authorization=m1.AUTH_INSTALLER)
    if host.service_lookup(m1.SERVICE_NAME)[0] != m1.PROBE_ABSENT:
        raise SystemExit('Fixture refuses to replace an existing service')
    root=Path('C:/NivXMigrationCI')
    if root.exists():raise SystemExit('Fixture root already exists')
    host.create_directory_protected(root)
    for name in ('sensor','state','tls'):
        host.create_directory_protected(root/name)
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'NivX ephemeral migration fixture')])
    now=datetime.datetime.now(datetime.timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
          .public_key(key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now-datetime.timedelta(minutes=5))
          .not_valid_after(now+datetime.timedelta(hours=2))
          .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True)
          .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False)
          .sign(key,hashes.SHA256()))
    certfile=root/'tls/test.crt';keyfile=root/'tls/test.key'
    host.write_new_file(certfile,cert.public_bytes(serialization.Encoding.PEM))
    host.write_new_file(keyfile,key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    thumb=cert.fingerprint(hashes.SHA1()).hex()
    subprocess.run(['certutil','-addstore','Root',str(certfile)],check=True,capture_output=True)
    observations={'sessions':0,'heartbeats':[],'capabilities':0,'fail_heartbeat':False}
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):self.reply({})
        def do_POST(self):
            body=json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))) or b'{}')
            if self.path.endswith('/session'):
                observations['sessions']+=1;self.reply({'session_token':'fixture-session'});return
            if self.path.endswith('/heartbeat'):
                if observations['fail_heartbeat']:
                    self.reply({'error':'fixture rejection'},503);return
                observations['heartbeats'].append(body.get('sensor_version'))
            if self.path.endswith('/forensic-capabilities'):observations['capabilities']+=1
            # Deliberately do NOT acknowledge event batches. Queue preservation
            # is checked while the service performs real authenticated heartbeats.
            self.reply({})
        def reply(self,body,code=200):
            raw=json.dumps(body).encode();self.send_response(code)
            self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)))
            self.end_headers();self.wfile.write(raw)
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(certfile,keyfile)
    server.socket=ctx.wrap_socket(server.socket,server_side=True)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    config_path=root/'m1-config.json'
    raw={'origin':f'https://127.0.0.1:{server.server_port}', 'tenant_id':'tenant-fixture',
         'install_dir':str(root/'sensor'),'state_dir':str(root/'state'),
         'service_exe':str(root/'sensor/NivXForgeSensor.exe'),
         'service_args':['--m1-service-run','--m1-config',str(config_path),'--state-dir',str(root/'state')],
         'certificate_policy':'windows-default','interval':5}
    host.write_new_file(config_path,json.dumps(raw).encode())
    identity=json.dumps({'endpoint_id':'ep_fixture_native','tenant_id':'tenant-fixture',
                         'agent_credential':'not-a-real-credential'}).encode()
    host.write_new_file(root/'state/identity.json',identity)
    config=m1.load_config(config_path,host)
    # The previous SCM fixture is a separate executable with a different hash.
    old=Path(sys.argv[1]);new=Path(sys.argv[2]);setup=Path(sys.argv[3])
    old_manifest={p.relative_to(old).as_posix():{'size':p.stat().st_size,'sha256':m1.file_digest(p)} for p in old.rglob('*') if p.is_file()}
    host.copy_payload(old,root/'sensor',old_manifest)
    owner=m1.Ownership(root/m1.OWNERSHIP_FILENAME,host);record=owner.create('native-fixture',config)
    for name in ('install_dir','state_dir','payload','enrollment'):owner.mark(record,name,m1.CREATE_CONFIRMED)
    binary=m1.verify_installed_binary(config,old_manifest,host)
    host.service_create(m1.SERVICE_NAME,m1._bin_path(config),start_type=m1.SERVICE_DISABLED)
    host.service_set_security(m1.SERVICE_NAME,m1.m1_service_descriptor())
    owner.mark(record,'service',m1.ACTIVATION_VERIFIED,{'bin_path':m1._bin_path(config),'service_image':binary})
    results={}
    try:
        host.service_set_start_type(m1.SERVICE_NAME,m1.SERVICE_DEMAND_START)
        host.service_start(m1.SERVICE_NAME)
        assert upgrade.image_running(host,config.service_exe,binary['sha256'])
        host.service_set_start_type(m1.SERVICE_NAME,m1.SERVICE_AUTO_START)
        def invoke(*args,expected=0):
            proc=subprocess.run([str(setup),*args],capture_output=True,text=True,timeout=480)
            if proc.returncode != expected:
                raise AssertionError(f'CLI failed {proc.returncode}: {proc.stderr[-2000:]} {proc.stdout[-2000:]}')
            return json.loads(proc.stdout)
        results['preflight']=invoke('m1-upgrade','--m1-config',str(config_path))
        results['upgrade']=invoke('m1-upgrade','--m1-config',str(config_path),'--apply')
        assert results['upgrade']['result']=='VERIFIED'
        assert (root/'state/identity.json').read_bytes()==identity
        assert '0.6.2-windows' in observations['heartbeats']
        assert observations['capabilities']>0
        # State written after activation must survive the explicit rollback.
        host.write_new_file(root/'state/retained-evidence.fixture',b'keep after rollback')
        results['rollback']=invoke('m1-rollback','--m1-config',str(config_path))
        assert results['rollback']['result']=='ROLLED_BACK'
        assert (root/'state/retained-evidence.fixture').read_bytes()==b'keep after rollback'
        assert m1.file_digest(Path(config.service_exe))==binary['sha256']
        results['identity_preserved']=True;results['live_state_preserved']=True
        results['real_scm_verified']=True;results['real_tls_heartbeat_verified']=True
        results['forensic_worker_advertised']=True
        results['observations']={'session_requests':observations['sessions'],
                                 'heartbeat_versions':observations['heartbeats'],
                                 'capability_advertisements':observations['capabilities']}
        Path('m1-native-validation.json').write_text(json.dumps(results,indent=2))
        print(json.dumps(results,indent=2))
    finally:
        host.service_stop(m1.SERVICE_NAME);host.service_delete(m1.SERVICE_NAME)
        server.shutdown()
        subprocess.run(['certutil','-delstore','Root',thumb],capture_output=True)


if __name__=='__main__':main()
