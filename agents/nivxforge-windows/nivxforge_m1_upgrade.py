"""Ownership-bound M1 payload upgrade. Never enrolls or rewinds evidence.

The existing SCM command, service ACL, config and identity remain authoritative.
An interrupted operation blocks another upgrade until explicit rollback. Payload
and a quiesced state backup are retained; rollback restores code, NOT live state.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import time
import uuid
import nivxforge_m1 as m1

OP_FILE = 'm1-upgrade.json'
TERMINAL = {'VERIFIED', 'ROLLED_BACK'}


def fail(code):
    raise m1.M1Error(code, 'Upgrade refused; existing enrollment is preserved.')


def protected(path, host, directory=False):
    path = Path(path)
    for ancestor in host.path_ancestry(path):
        if host.is_reparse_point(ancestor) is not False:
            fail('UPGRADE_PATH_UNSAFE')
    acl = (host.directory_security(path, role=m1.ROLE_OWNED) if directory
           else host.file_security(path))
    if acl is None or acl.get('nonadmin_writable'):
        fail('UPGRADE_ACL_UNSAFE')


def manifest_for(root, host):
    root = Path(root)
    protected(root, host, True)
    out = {}
    for path in sorted(root.rglob('*')):
        protected(path, host, path.is_dir())
        if path.is_file():
            out[path.relative_to(root).as_posix()] = {
                'size': path.stat().st_size, 'sha256': m1.file_digest(path)}
    return out


def identity_digest(config, host):
    path = config.state_dir / 'identity.json'
    protected(path, host)
    body = host.read_bytes(path)
    try:
        identity = json.loads(body)
    except ValueError:
        fail('UPGRADE_IDENTITY_INVALID')
    if (identity.get('tenant_id') != config.tenant_id
            or not identity.get('endpoint_id')
            or not identity.get('agent_credential')):
        fail('UPGRADE_IDENTITY_MISMATCH')
    return hashlib.sha256(body).hexdigest(), identity['endpoint_id']


def preflight(config_path, host, *, allow_pending=False):
    config = m1.load_config(config_path, host)
    root = Path(config_path).parent
    protected(root, host, True)
    # Only the established sibling layout is supported, never arbitrary roots.
    if (config.install_dir.parent != root or config.state_dir.parent != root
            or config.install_dir == config.state_dir
            or Path(config.service_exe) != config.install_dir / 'NivXForgeSensor.exe'):
        fail('UPGRADE_LAYOUT_UNSUPPORTED')
    for path in (config.install_dir, config.state_dir):
        protected(path, host, True)
    owner = m1.Ownership(root / m1.OWNERSHIP_FILENAME, host)
    protected(owner.path, host)
    record = owner.read()
    if owner.blocking(record) or any(not owner.owns(record, r)
                                   for r in ('service', 'payload', 'enrollment', 'install_dir', 'state_dir')):
        fail('UPGRADE_OWNERSHIP_UNCONFIRMED')
    if record.get('config') != config.as_record():
        fail('UPGRADE_CONFIG_DRIFT')
    qc = host.service_qc(m1.SERVICE_NAME)
    evidence = record['resources']['service']['evidence']
    if (not qc or qc.get('bin_path') != m1._bin_path(config)
            or qc.get('bin_path') != evidence.get('bin_path')
            or qc.get('account') != 'LocalSystem'):
        fail('UPGRADE_SERVICE_MISMATCH')
    sd = host.service_security(m1.SERVICE_NAME)
    if sd is None or not m1.service_security_verdict(sd, host)['safe']:
        fail('UPGRADE_SERVICE_ACL_UNSAFE')
    expected = evidence.get('service_image', {}).get('sha256')
    if not expected or m1.file_digest(Path(config.service_exe)) != expected:
        fail('UPGRADE_OLD_IMAGE_DRIFT')
    if qc.get('state') == m1.SERVICE_RUNNING:
        running = host.verify_running_image(m1.SERVICE_NAME, config.service_exe, expected_sha256=expected)
        if not running or running.get('verdict') != 'MATCH':
            fail('UPGRADE_RUNNING_IMAGE_MISMATCH')
    if not allow_pending and (root / OP_FILE).exists():
        protected(root / OP_FILE, host)
        if json.loads(host.read_bytes(root / OP_FILE)).get('phase') not in TERMINAL:
            fail('UPGRADE_RECOVERY_REQUIRED')
    digest, endpoint = identity_digest(config, host)
    return config, owner, record, qc, digest, endpoint


def plan(config_path, host):
    c, _, _, qc, _, endpoint = preflight(config_path, host)
    return {'result': 'READY_FOR_STAGING', 'endpoint_id': endpoint,
            'origin': c.origin, 'service': m1.SERVICE_NAME,
            'service_state': qc['state'], 'install_dir': str(c.install_dir),
            'state_dir': str(c.state_dir), 're_enrollment': False,
            'note': 'Read-only compatibility check; no service or file changed.'}


def save(root, op, host, phase):
    op['phase'] = phase
    body = json.dumps(op, indent=2, sort_keys=True).encode()
    path = root / OP_FILE
    if path.exists():
        protected(path, host)
        host.replace_file(path, body)
    else:
        host.write_new_file(path, body)


def stop_proven(host):
    qc = host.service_qc(m1.SERVICE_NAME)
    if not qc:
        fail('UPGRADE_STOP_UNKNOWN')
    pid = qc.get('pid', 0)
    identity = host.process_identity(pid) if pid else None
    if pid and not identity:
        fail('UPGRADE_PROCESS_UNKNOWN')
    host.service_set_start_type(m1.SERVICE_NAME, m1.SERVICE_DISABLED)
    if host.service_qc(m1.SERVICE_NAME).get('start_type_code') != m1.SERVICE_DISABLED:
        fail('UPGRADE_DISABLE_UNPROVEN')
    if host.service_stop(m1.SERVICE_NAME) != 'STOPPED':
        fail('UPGRADE_STOP_UNPROVEN')
    if pid and host.process_exited(pid, identity) is not True:
        fail('UPGRADE_PROCESS_EXIT_UNPROVEN')


def image_running(host, exe, digest, timeout=60):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        result = host.verify_running_image(m1.SERVICE_NAME, str(exe), expected_sha256=digest)
        if result and result.get('verdict') == 'MATCH':
            return True
        time.sleep(1)
    return False


def healthy(config, op, host):
    path = config.state_dir / 'm1-runtime-health.json'
    if not path.exists():
        return False
    protected(path, host)
    try:
        report = json.loads(host.read_bytes(path))
    except ValueError:
        return False
    qc = host.service_qc(m1.SERVICE_NAME)
    return bool(qc and report.get('pid') == qc.get('pid')
                and report.get('at_epoch', 0) >= op['started_at']
                and report.get('sensor_version') == op['target_version']
                and report.get('endpoint_id') == op['endpoint_id']
                and report.get('forensic_worker_started') is True
                and report.get('backend_acknowledged') is True)


def restore(config, op, host, owner, old_record):
    root = config.config_path.parent
    work = Path(op['work'])
    # Paths are derived from the protected root, not trusted from arbitrary JSON.
    if work.parent != root or not work.name.startswith('.m1-upgrade-'):
        fail('UPGRADE_RECOVERY_PATH_INVALID')
    protected(work, host, True)
    if Path(config.service_exe).exists() and m1.file_digest(Path(config.service_exe)) not in (op['old_sha256'], op['new_sha256']):
        fail('UPGRADE_RECOVERY_IMAGE_DRIFT')
    stop_proven(host)
    old = work / 'previous-payload'
    if old.exists():
        old_manifest = json.loads(host.read_bytes(work / 'previous-manifest.json'))
        m1.m1_payload_check(old, config.install_dir, old_manifest, host)
        if config.install_dir.exists():
            if (work / 'failed-payload').exists():
                fail('UPGRADE_RECOVERY_AMBIGUOUS')
            os.rename(config.install_dir, work / 'failed-payload')
        os.rename(old, config.install_dir)
    if m1.file_digest(Path(config.service_exe)) != op['old_sha256']:
        fail('UPGRADE_ROLLBACK_IMAGE_MISMATCH')
    # Never restore state-backup over live state: that can resurrect delivered
    # rows and lose newly acquired evidence. The old and new journal schema agree.
    if identity_digest(config, host)[0] != op['identity_sha256']:
        fail('UPGRADE_ROLLBACK_IDENTITY_DRIFT')
    owner.save(old_record)
    if op['was_running']:
        host.service_set_start_type(m1.SERVICE_NAME, m1.SERVICE_DEMAND_START)
        host.service_start(m1.SERVICE_NAME)
        if not image_running(host, config.service_exe, op['old_sha256']):
            fail('UPGRADE_ROLLBACK_START_FAILED')
    host.service_set_start_type(m1.SERVICE_NAME, op['start_type_code'])
    if host.service_qc(m1.SERVICE_NAME).get('start_type_code') != op['start_type_code']:
        fail('UPGRADE_ROLLBACK_START_TYPE_FAILED')
    save(root, op, host, 'ROLLED_BACK')
    return {'result': 'ROLLED_BACK', 'backup': str(work), 'live_evidence_preserved': True}


def upgrade(config_path, host, payload, manifest, version, *, timeout=300):
    with host.exclusive_lock() as lock:
        if lock is None:
            fail('UPGRADE_CONCURRENT_OPERATION')
        c, owner, record, qc, ident, endpoint = preflight(config_path, host)
        root = c.config_path.parent
        work = root / ('.m1-upgrade-' + uuid.uuid4().hex)
        m1.m1_payload_check(payload, c.install_dir, manifest, host)
        if 'NivXForgeSensor.exe' not in manifest:
            fail('UPGRADE_PAYLOAD_NO_SERVICE')
        host.create_directory_protected(work)
        stage = work / 'new-payload'
        host.create_directory_protected(stage)
        host.copy_payload(payload, stage, manifest)
        m1.m1_payload_check(stage, c.install_dir, manifest, host)
        op = {'schema': 1, 'work': str(work), 'config_sha256': c.config_digest,
              'endpoint_id': endpoint, 'identity_sha256': ident,
              'old_sha256': m1.file_digest(Path(c.service_exe)),
              'new_sha256': manifest['NivXForgeSensor.exe']['sha256'],
              'target_version': version, 'started_at': time.time(),
              'was_running': qc['state'] == m1.SERVICE_RUNNING,
              'start_type_code': qc['start_type_code']}
        host.write_new_file(work / 'ownership-backup.json', owner._envelope(record))
        host.write_new_file(work / 'config-backup.json', host.read_bytes(c.config_path))
        save(root, op, host, 'STAGED')
        try:
            stop_proven(host)
            save(root, op, host, 'STOPPED')
            state_manifest = manifest_for(c.state_dir, host)
            host.create_directory_protected(work / 'state-backup')
            host.copy_payload(c.state_dir, work / 'state-backup', state_manifest)
            m1.m1_payload_check(work / 'state-backup', c.state_dir, state_manifest, host)
            old_manifest = manifest_for(c.install_dir, host)
            host.write_new_file(work / 'previous-manifest.json', json.dumps(old_manifest).encode())
            if identity_digest(c, host)[0] != ident:
                fail('UPGRADE_IDENTITY_DRIFT')
            if m1.file_digest(c.config_path) != c.config_digest:
                fail('UPGRADE_CONFIG_DRIFT')
            save(root, op, host, 'BACKED_UP')
            os.rename(c.install_dir, work / 'previous-payload')
            save(root, op, host, 'OLD_MOVED')
            os.rename(stage, c.install_dir)
            save(root, op, host, 'NEW_ACTIVE')
            m1.verify_installed_binary(c, manifest, host)
            host.service_set_start_type(m1.SERVICE_NAME, m1.SERVICE_DEMAND_START)
            host.service_start(m1.SERVICE_NAME)
            save(root, op, host, 'STARTING')
            if not image_running(host, c.service_exe, op['new_sha256']):
                fail('UPGRADE_NEW_IMAGE_NOT_RUNNING')
            until = time.monotonic() + timeout
            while not healthy(c, op, host):
                if time.monotonic() >= until:
                    fail('UPGRADE_BACKEND_ACK_TIMEOUT')
                time.sleep(2)
            if identity_digest(c, host)[0] != ident:
                fail('UPGRADE_IDENTITY_DRIFT')
            binary = m1.verify_installed_binary(c, manifest, host)
            owner.mark(record, 'payload', m1.CREATE_CONFIRMED,
                       {'members': len(manifest), 'service_image': binary})
            owner.mark(record, 'service', m1.ACTIVATION_VERIFIED,
                       {**record['resources']['service']['evidence'], 'service_image': binary,
                        'upgrade_version': version, 'upgrade_backup': str(work)})
            host.service_set_start_type(m1.SERVICE_NAME, op['start_type_code'])
            if host.service_qc(m1.SERVICE_NAME).get('start_type_code') != op['start_type_code']:
                fail('UPGRADE_START_TYPE_UNVERIFIED')
            save(root, op, host, 'VERIFIED')
            return {'result': 'VERIFIED', 'endpoint_id': endpoint,
                    'sensor_version': version, 'backup': str(work), 're_enrolled': False}
        except Exception:
            # Restore from the immutable pre-upgrade record, never the mutated one.
            old_record = m1.Ownership(work / 'ownership-backup.json', host).read()
            try:
                restore(c, op, host, owner, old_record)
            except Exception:
                save(root, op, host, 'RECOVERY_REQUIRED')
                fail('UPGRADE_RECOVERY_REQUIRED')
            raise


def rollback(config_path, host):
    with host.exclusive_lock() as lock:
        if lock is None:
            fail('UPGRADE_CONCURRENT_OPERATION')
        c = m1.load_config(config_path, host)
        root = c.config_path.parent
        protected(root / OP_FILE, host)
        op = json.loads(host.read_bytes(root / OP_FILE))
        if op.get('phase') == 'ROLLED_BACK':
            return {'result': 'ROLLED_BACK', 'already_restored': True}
        if op.get('config_sha256') != c.config_digest:
            fail('UPGRADE_CONFIG_DRIFT')
        qc = host.service_qc(m1.SERVICE_NAME)
        if not qc or qc.get('bin_path') != m1._bin_path(c) or qc.get('account') != 'LocalSystem':
            fail('UPGRADE_SERVICE_MISMATCH')
        work = Path(op['work'])
        if work.parent != root or not work.name.startswith('.m1-upgrade-'):
            fail('UPGRADE_RECOVERY_PATH_INVALID')
        protected(work / 'ownership-backup.json', host)
        old = m1.Ownership(work / 'ownership-backup.json', host).read()
        return restore(c, op, host, m1.Ownership(root / m1.OWNERSHIP_FILENAME, host), old)
