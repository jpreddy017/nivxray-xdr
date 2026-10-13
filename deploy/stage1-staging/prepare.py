#!/usr/bin/env python3
"""Verify pinned Git objects and export clean build contexts; never deploy."""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import urllib.parse

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCE = json.loads((HERE / 'source.json').read_text())
PRODUCTION_HOSTS = {'nivxray.nivxforge.com', 'xdr.nivxforge.com',
                    'edr.nivxforge.com', 'xdr.nivxray.com'}


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT)


def origin(value):
    parsed = urllib.parse.urlsplit(value)
    host = parsed.hostname or ''
    if (parsed.scheme != 'https' or not host or parsed.username or parsed.password
            or parsed.path not in ('', '/') or parsed.query or parsed.fragment
            or parsed.port not in (None, 443) or host in PRODUCTION_HOSTS
            or host in ('localhost', '127.0.0.1')
            or host.endswith(('.invalid', '.example', '.test'))
            or 'preview.emergentagent.com' in host):
        raise ValueError('Use an owner-verified isolated HTTPS origin')
    return 'https://' + host


def verify_source():
    sha = SOURCE['commit']
    if git('rev-parse', sha + '^{tree}').decode().strip() != SOURCE['tree']:
        raise ValueError('Source tree mismatch')
    changes = git('diff', '--name-only', sha, 'HEAD').decode().splitlines()
    if any(not (p.startswith('deploy/stage1-staging/') or
                p == '.github/workflows/stage1-staging-package.yml') for p in changes):
        raise ValueError('Candidate includes changes outside staging packaging')
    subprocess.run(['git', 'merge-base', '--is-ancestor', sha, 'HEAD'],
                   cwd=ROOT, check=True, capture_output=True)


def included(path):
    p = pathlib.PurePosixPath(path)
    if any(part.startswith('.') for part in p.parts):
        return False
    if p.suffix.lower() in ('.db', '.sqlite', '.sqlite3', '.pem', '.key', '.tok'):
        return False
    if path.startswith('backend/'):
        return not path.startswith(('backend/tests/', 'backend/docs/',
            'backend/exports/', 'backend/xdr_state/', 'backend/test_reports/'))
    return (path.startswith(('apps/nivxray-xdr/src/', 'apps/nivxray-xdr/scripts/'))
            or path in {'apps/nivxray-xdr/package.json', 'apps/nivxray-xdr/yarn.lock',
                        'apps/nivxray-xdr/vite.config.js', 'apps/nivxray-xdr/index.html'})


def export(destination, api_origin):
    verify_source()
    api_origin = origin(api_origin)
    dest = pathlib.Path(destination).resolve()
    if dest.exists() or dest.is_relative_to(ROOT):
        raise ValueError('Use a new context directory outside the repository')
    entries = git('ls-tree', '-rz', '--full-tree', SOURCE['commit']).split(b'\0')
    manifest = []
    # Select tracked application bytes only; never copy the working directory,
    # runtime data, .env, private keys, bundled source exports or other branches.
    for entry in entries:
        if not entry:
            continue
        metadata, raw_path = entry.split(b'\t', 1)
        mode, kind, sha = metadata.decode().split()
        path = raw_path.decode()
        if not included(path):
            continue
        if mode not in ('100644', '100755') or kind != 'blob':
            raise ValueError('Unsupported selected Git object')
        content = git('cat-file', 'blob', sha)
        target = dest / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        target.chmod(0o755 if mode == '100755' else 0o644)
        manifest.append({'path': path, 'git_blob': sha,
                         'sha256': hashlib.sha256(content).hexdigest()})
    config = json.loads((HERE / 'vercel.json').read_text())
    csp = config['headers'][0]['headers'][0]
    csp['value'] = csp['value'].replace('https://stage1-api.invalid', api_origin)
    csp['value'] = csp['value'].replace('wss://stage1-api.invalid',
                                      api_origin.replace('https://', 'wss://'))
    (dest / SOURCE['frontend'] / 'vercel.json').write_text(
        json.dumps(config, indent=2) + '\n')
    (dest / 'backend.Dockerfile').write_bytes((HERE / 'backend.Dockerfile').read_bytes())
    (dest / '.dockerignore').write_text('**/.env*\n**/node_modules\n**/dist\n**/__pycache__\n**/*.pyc\n')
    record = {'source': SOURCE, 'api_origin': api_origin, 'files': manifest,
              'overlay_sha256': hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()}
    (dest / 'source-manifest.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({'context': str(dest), 'commit': SOURCE['commit'],
                      'tree': SOURCE['tree'], 'files': len(manifest)}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--context')
    parser.add_argument('--api-origin')
    parser.add_argument('--verify-only', action='store_true')
    args = parser.parse_args()
    if args.verify_only:
        verify_source()
        print('Pinned source verified')
    elif args.context and args.api_origin:
        export(args.context, args.api_origin)
    else:
        parser.error('Supply --verify-only or both --context and --api-origin')
