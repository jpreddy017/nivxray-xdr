#!/usr/bin/env python3
"""Offline admission checks for owner-provisioned staging config. Names only."""
import argparse
import os
import pathlib
import re
import urllib.parse
from prepare import HERE, ROOT, origin, verify_source


def read_env(path, template):
    path = pathlib.Path(path).resolve()
    if path.is_relative_to(ROOT) or not path.is_file():
        raise ValueError('Secret/config files must exist outside the repository')
    if os.name == 'posix' and path.stat().st_mode & 0o077:
        raise ValueError('Config files must have private permissions (0600)')
    allowed = {l.split('=', 1)[0] for l in (HERE / template).read_text().splitlines()
               if l and not l.startswith('#')}
    result = {}
    for line in path.read_text().splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        key, separator, value = line.partition('=')
        if not separator or key not in allowed or key in result or not value.strip():
            raise ValueError('Unknown, duplicate, missing or empty configuration field')
        if value != value.strip() or value.startswith(('"', "'")) or '${' in value:
            raise ValueError('Use literal unquoted values; no interpolation')
        result[key] = value
    if set(result) != allowed:
        raise ValueError('Required configuration names missing')
    return result


def validate(compose, backend, mongo):
    for key in ('MONGO_IMAGE', 'BACKEND_IMAGE', 'NGINX_IMAGE'):
        if not re.fullmatch(r'[a-zA-Z0-9./_:-]+@sha256:[0-9a-f]{64}', compose[key]):
            raise ValueError('Images must use reviewed sha256 digest references')
    origin(compose['STAGING_FRONTEND_ORIGIN'])
    if mongo['MONGO_INITDB_DATABASE'] != 'nivxray_stage1_staging':
        raise ValueError('Wrong database')
    uri = urllib.parse.urlsplit(backend['MONGO_URL'])
    if (uri.scheme != 'mongodb' or uri.hostname != 'mongodb' or uri.port != 27017
            or uri.path != '/nivxray_stage1_staging'
            or urllib.parse.parse_qs(uri.query) != {'authSource': ['nivxray_stage1_staging']}
            or urllib.parse.unquote(uri.username or '') != mongo['STAGING_MONGO_USER']
            or urllib.parse.unquote(uri.password or '') != mongo['STAGING_MONGO_PASSWORD']):
        raise ValueError('Mongo must use the private staging app account and database')
    if mongo['MONGO_INITDB_ROOT_USERNAME'] == mongo['STAGING_MONGO_USER']:
        raise ValueError('Application must not use Mongo root authority')
    if mongo['MONGO_INITDB_ROOT_PASSWORD'] == mongo['STAGING_MONGO_PASSWORD']:
        raise ValueError('Mongo root and app credentials must differ')
    keys = ['JWT_SECRET', 'EDR_AUTH_PEPPER', 'XDR_AUDIT_MASTER_SECRET',
            'XDR_SECRETS_MASTER', 'NIVXRAY_SIGNING_SECRET', 'XDR_ROOT_KEY']
    if len({backend[k] for k in keys}) != len(keys):
        raise ValueError('Cryptographic purposes require distinct staging secrets')
    for key in keys:
        if len(backend[key]) < 32 or any(x in backend[key].lower()
                for x in ('placeholder', 'changeme', 'dummy', 'example', 'todo')):
            raise ValueError('Invalid staging cryptographic secret')
    for key in ('EDR_ENROLLMENT_TOKEN_TTL_SECONDS', 'EDR_AGENT_SESSION_TTL_SECONDS', 'JWT_EXPIRE_HOURS'):
        if not backend[key].isdigit() or int(backend[key]) < 1:
            raise ValueError('Invalid positive TTL setting')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    args = parser.parse_args()
    try:
        verify_source()
        compose = read_env(args.config, 'compose.env.example')
        backend = read_env(compose['BACKEND_ENV_FILE'], 'backend.env.example')
        mongo = read_env(compose['MONGO_ENV_FILE'], 'mongo.env.example')
        validate(compose, backend, mongo)
    except Exception:
        # URL parsing and filesystem exceptions may contain secret-bearing input.
        raise SystemExit('BLOCKED: staging configuration failed offline validation; no values disclosed')
    print('PASS: offline configuration checks only; host/network acceptance remains HOLD')
