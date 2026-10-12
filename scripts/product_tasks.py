#!/usr/bin/env python3
"""Local-only product build/test entry points. No deploy, account or migration commands."""
import argparse
import glob
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def manifest():
    return json.loads((ROOT / 'products/manifest.json').read_text())


def check():
    data=manifest()
    if set(data['products']) != {'company','workspace','xdr','edr'}:
        raise ValueError('Exactly the four declared products must be mapped')
    for product in data['products'].values():
        for relative in product.get('source_roots',[]) + product.get('backend_modules',[]):
            path=(ROOT/relative).resolve()
            if not path.is_relative_to(ROOT) or not path.exists():
                raise ValueError('Missing or unsafe mapped source: '+relative)
    for paths in data['shared'].values():
        for relative in paths:
            if not (ROOT/relative).exists():raise ValueError('Missing shared source: '+relative)
    print('Ownership map valid; company website explicitly unresolved')


def command(product, action):
    item=manifest()['products'][product]
    if item['status'] != 'existing':raise ValueError(item['blocked_reason'])
    cwd=ROOT/item['build_root']
    env=os.environ.copy()
    # This is a local proof build, not the existing production deploy script.
    # Explicit public test origins prevent accidental production API defaults.
    env.update(REACT_APP_BACKEND_URL='http://127.0.0.1:9',
               REACT_APP_NIVXRAY_API_URL='http://127.0.0.1:9',
               REACT_APP_XDR_URL='',REACT_APP_EDR_URL='',REACT_APP_WORKSPACE_URL='',
               VITE_XDR_URL='',VITE_EDR_URL='',VITE_WORKSPACE_URL='')
    output=ROOT/'.build/products'/product
    if product in ('xdr','edr'):
        env['REACT_APP_PRODUCT_SCOPE']=product
        if action=='build':
            args=['npm','run','build','--','--outDir',str(output),'--emptyOutDir']
        else:
            args=['npm','run','test','--','--config',f'vitest.{product}.config.js']
    elif action=='build':
        env.update(BUILD_PATH=str(output), GENERATE_SOURCEMAP='false', CI='true',
                   REACT_APP_NIVX_FLAG_TRAJECTORY_ENGINE='disabled',
                   REACT_APP_NIVX_FLAG_CASE_ENGINE='disabled',
                   REACT_APP_NIVX_FLAG_VERDICT_ENGINE_V3='disabled')
        args=['npm','run','build']
    else:
        # Existing dependency-free Node regressions. The CRA viewport suite is
        # a separate browser/Jest gate; this command does not pretend to run it.
        cases=sorted(glob.glob(str(cwd/'src/components/__tests__/*.test.mjs')))
        if not cases:raise ValueError('No existing Workspace Node regressions found')
        args=['node','--test',*cases]
    return args,cwd,env


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('product',choices=['company','workspace','xdr','edr','all'])
    parser.add_argument('action',choices=['check','build','test'])
    options=parser.parse_args()
    try:
        if options.action=='check':check();return 0
        if options.product=='all':raise ValueError('Choose one product for build/test; company source is unresolved')
        args,cwd,env=command(options.product,options.action)
        return subprocess.run(args,cwd=cwd,env=env,check=False).returncode
    except ValueError as error:
        print('BLOCKED: '+str(error),file=sys.stderr);return 2


if __name__=='__main__':sys.exit(main())
