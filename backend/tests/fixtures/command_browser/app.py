"""Loopback-only test fixture; never mounted by the production application."""
import os
import secrets
from pathlib import Path
import jwt
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import deps
from routers.ops import router

if os.environ.get('NIVX_COMMAND_BROWSER_TEST') != 'synthetic-loopback-only':
    raise RuntimeError('Synthetic browser fixture requires explicit test opt-in')

deps.JWT_SECRET = secrets.token_hex(32)
class Users:
    async def find_one(self, query, projection):
        if query['email'] == 'command-browser@synthetic.invalid':
            return {'email':query['email'], 'role':'analyst'}
class DB:
    users = Users()
deps.db = DB()
app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=['http://127.0.0.1:3197'], allow_methods=['POST'], allow_headers=['Authorization','Content-Type','X-Tenant-Id'])
app.include_router(router, prefix='/api')
# Ephemeral test credential only; never print or commit it.
Path(os.environ['NIVX_COMMAND_TEST_TOKEN_PATH']).write_text(jwt.encode({'sub':'command-browser@synthetic.invalid'},deps.JWT_SECRET,algorithm='HS256'))
