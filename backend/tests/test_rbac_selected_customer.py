"""RBAC-2: real dependency, tenant resolver, permission authority and JWT validation.
Storage is exclusively synthetic in-memory data; no server startup or network.
"""
import copy
import hashlib
import secrets
import socket
from types import SimpleNamespace

import pytest
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

import deps
from routers import xdr_rbac as rb
from services import tenant_registry as registry


class Collection:
    def __init__(self, rows=()): self.rows = list(rows)
    def find_one(self, query, projection=None):
        return next((copy.deepcopy(row) for row in self.rows if all(row.get(k) == v for k,v in query.items())), None)
    def find(self, query, projection=None):
        return [copy.deepcopy(row) for row in self.rows if all(row.get(k) == v for k,v in query.items())]
    def update_one(self, *args, **kwargs): pass


@pytest.fixture
def env(monkeypatch):
    def blocked(*args, **kwargs): raise AssertionError("Network forbidden in deterministic tests")
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    user = {"email": "synthetic@example.com", "tenant_id": "A", "tenant_ids": ["A","B"], "role": "analyst"}
    class AuthUsers:
        async def find_one(self, query, projection=None): return dict(user) if query.get("email") == user["email"] else None
    monkeypatch.setattr(deps, "db", SimpleNamespace(users=AuthUsers()))
    monkeypatch.setattr(deps, "JWT_SECRET", secrets.token_hex(32))
    monkeypatch.setattr(rb, "_JWT_SECRET", deps.JWT_SECRET)
    class Identity:
        def find_one(self, query, projection=None): return dict(user) if query.get("email") == user["email"] else None
    monkeypatch.setattr(deps, "sync_collection", lambda name: Identity() if name == "users" else None)
    tenants = {t: {"id": t, "state":"ACTIVE", "organization_id":"O"} for t in ["A","B","C"]}
    monkeypatch.setattr(registry, "get_tenant", lambda t: copy.deepcopy(tenants.get(t)))
    monkeypatch.setattr(registry, "get_organization", lambda o: {"id":"O","state":"ACTIVE"} if o=="O" else None)
    users = Collection([{"id":"uA","tenant_id":"A","email":user["email"],"enabled":True},
                        {"id":"uB","tenant_id":"B","email":user["email"],"enabled":True}])
    roles = Collection([{"id":"rA","name":"synthetic-a","permissions":["secrets.read","users.read"],"enabled":True},
                        {"id":"rB","name":"synthetic-b","permissions":["users.read"],"enabled":True}])
    assignments = Collection([{"id":"aA","user_id":"uA","tenant_id":"A","role_id":"rA","scope":{}},
                              {"id":"aB","user_id":"uB","tenant_id":"B","role_id":"rB","scope":{}}])
    grants, restrictions = Collection(), Collection()
    for name, collection in [("_c_users",users),("_c_roles",roles),("_c_assignments",assignments),
                             ("_c_groups",Collection()),("_c_grants",grants),("_c_restrictions",restrictions)]:
        monkeypatch.setattr(rb, name, lambda collection=collection: collection)
    audits=[]
    monkeypatch.setattr(rb,"emit_audit",lambda **kw:(audits.append(kw) or {"id":"synthetic-audit"}))
    app=FastAPI(); app.include_router(rb.router)
    @app.get("/probe",dependencies=[Depends(rb.require_permission("secrets.read"))])
    def probe(request:Request): return {"tenant":rb.resolve_principal(request)[0]}
    @app.get("/userscope/{user_id}",dependencies=[Depends(rb.require_permission("users.read",resource_id_header="X-Resource-Id"))])
    def record(user_id:str,request:Request):
        tenant=rb.resolve_principal(request)[0]; row=rb._user_by_id(tenant,user_id)
        if not row: raise HTTPException(404,detail="not found")
        return {"id":row["id"],"tenant":tenant}
    @app.post("/body",dependencies=[Depends(rb.require_permission("users.read"))])
    async def body(request:Request): return {"tenant":rb.resolve_principal(request)[0]}
    raw= "nvx_"+secrets.token_hex(24)
    keys=Collection([{"_id":"keyA","id":"keyA","hash":hashlib.sha256(raw.encode()).hexdigest(),"tenant_id":"A","scopes":["secrets.read"],"revoked":False,"enabled":True}])
    monkeypatch.setattr(rb,"_c_api_keys",lambda:keys)
    monkeypatch.setattr(rb,"_throttle",lambda *args,**kw:{"remaining":100})
    headers={"Authorization":"Bearer "+deps.create_token(user["email"])}
    with TestClient(app) as client:
        yield SimpleNamespace(client=client,user=user,users=users,roles=roles,assignments=assignments,
            grants=grants,restrictions=restrictions,tenants=tenants,headers=headers,key=raw,audits=audits)


def get(env,path="/probe",tenant=None,**kwargs):
    headers=dict(env.headers)
    if tenant is not None: headers["X-Tenant-Id"]=tenant
    headers.update(kwargs.pop("headers",{}))
    return env.client.get(path,headers=headers,**kwargs)


def test_a_b_permissions_and_projection_agree(env):
    assert get(env,tenant="A").json()=={"tenant":"A"}
    assert get(env,tenant="B").status_code==403
    for tenant,allowed in [("A",True),("B",False)]:
        response=get(env,"/api/xdr/rbac/me/effective",tenant)
        assert response.status_code==200
        data=response.json()["data"]
        assert data["tenant"]==tenant
        assert ("secrets.read" in data["permissions"])==allowed
        assert data["cross_tenant"] is False


def test_home_is_compatibility_request_not_authority(env):
    assert get(env).json()=={"tenant":"A"}
    env.user["tenant_ids"]=["B"]
    assert get(env).status_code==403


def test_single_customer_without_home_resolves_only_grant(env):
    env.user.pop("tenant_id");env.user["tenant_ids"]=["A"]
    assert get(env).json()=={"tenant":"A"}


def test_missing_multicustomer_selection_denied(env):
    env.user.pop("tenant_id")
    assert get(env).status_code==403


@pytest.mark.parametrize("path,headers",[
    ("/probe",{"X-Tenant-Id":"C"}), ("/probe?tenant_id=C",{}),
    ("/probe?customer=C",{}), ("/probe?tenant=C",{}),
    ("/probe?tenant_id=B",{"X-Tenant-Id":"A"}),
    ("/probe?tenant_id=A&tenant_id=B",{}), ("/probe?tenant_id=",{}),
    ("/probe?customer_id=C",{}), ("/probe?tenant_id=GHOST",{}),
])
def test_forged_or_conflicting_customer_denied(env,path,headers):
    assert get(env,path,headers=headers).status_code==403


def test_duplicate_conflicting_headers_denied(env):
    headers=list(env.headers.items())+[("X-Tenant-Id","A"),("X-Tenant-Id","B")]
    assert env.client.get("/probe",headers=headers).status_code==403


def test_body_customer_is_same_context_handler_uses(env):
    response=env.client.post("/body",headers=env.headers,json={"tenant_id":"B"})
    assert response.status_code==200 and response.json()["tenant"]=="B"
    response=env.client.post("/body",headers={**env.headers,"X-Tenant-Id":"A"},json={"tenant_id":"B"})
    assert response.status_code==403
    assert env.client.post("/body",headers=env.headers,json={"tenant_id":"C"}).status_code==403


@pytest.mark.parametrize("condition,basis",[("missing","USER_NOT_PROVISIONED"),("disabled","USER_DISABLED")])
def test_missing_disabled_memberships_never_inherit_home_permissions(env,condition,basis):
    if condition=="missing": env.users.rows.pop()
    else: env.users.rows[1]["enabled"]=False
    assert get(env,tenant="B").status_code==403
    data=get(env,"/api/xdr/rbac/me/effective","B").json()["data"]
    assert data["tenant"]=="B" and data["basis"]==basis and data["permissions"]==[]


def test_role_label_admin_cannot_bypass_selected_membership(env):
    env.user["role"]="admin"
    assert get(env,tenant="B").status_code==403
    assert get(env,tenant="C").status_code==403
    assert "secrets.read" not in get(env,"/api/xdr/rbac/me/effective","B").json()["data"]["permissions"]


def test_changed_grants_and_restrictions_have_no_stale_permissions(env):
    assert get(env,tenant="A").status_code==200
    env.roles.rows[0]["permissions"]=["users.read"]
    assert get(env,tenant="A").status_code==403
    env.roles.rows[0]["permissions"].append("secrets.read")
    env.restrictions.rows.append({"id":"deny","tenant_id":"A","user_id":"uA","permissions":["secrets.read"]})
    assert get(env,tenant="A").status_code==403
    assert "secrets.read" not in get(env,"/api/xdr/rbac/me/effective","A").json()["data"]["permissions"]


def test_resource_handler_ownership_uses_selected_customer(env):
    assert get(env,"/userscope/uB","B").json()=={"id":"uB","tenant":"B"}
    foreign=get(env,"/userscope/uA","B");missing=get(env,"/userscope/missing","B")
    assert foreign.status_code==missing.status_code==404
    assert foreign.json()==missing.json()


def test_resource_scope_and_forged_resource_header(env):
    env.assignments.rows[0]["scope"]={"resource_ids":["uA"]}
    assert get(env,"/userscope/uA","A").status_code==200
    assert get(env,"/userscope/missing","A").status_code==403
    assert get(env,"/userscope/missing","A",headers={"X-Resource-Id":"uA"}).status_code==403
    env.assignments.rows[0]["scope"]={"resource_ids":["another"]}
    assert get(env,"/userscope/uA","A").status_code==403


def test_resource_limited_grant_cannot_read_unbounded_list(env):
    env.assignments.rows[0]["scope"]={"resource_ids":["A-secret"]}
    assert get(env,tenant="A").status_code==403
    env.assignments.rows.clear()
    env.grants.rows.append({"id":"limited","tenant_id":"A","user_id":"uA","permissions":["secrets.read"],"scope":{"resource_ids":["A-secret"]}})
    assert get(env,tenant="A").status_code==403


@pytest.mark.parametrize("failure",["suspended","organization","registry","rbac"])
def test_unavailable_or_inactive_authority_fails_closed(env,monkeypatch,failure):
    if failure=="suspended": env.tenants["A"]["state"]="SUSPENDED"
    elif failure=="organization": monkeypatch.setattr(registry,"get_organization",lambda key:{"state":"SUSPENDED"})
    elif failure=="rbac": monkeypatch.setattr(rb,"_c_users",lambda:None)
    else:
        def down(key): raise RuntimeError("synthetic unavailable registry")
        monkeypatch.setattr(registry,"get_tenant",down)
    assert get(env).status_code in (403,503)
    assert get(env,"/api/xdr/rbac/me/effective").status_code in (403,503)


def test_machine_binding_and_ambiguous_credentials_preserved(env):
    assert env.client.get("/probe",headers={"X-XDR-API-Key":env.key,"X-Tenant-Id":"A"}).json()=={"tenant":"A"}
    assert env.client.get("/probe",headers={"X-XDR-API-Key":env.key,"X-Tenant-Id":"B"}).status_code in (401,403)
    ambiguous=get(env,headers={"X-XDR-API-Key":env.key,"X-Tenant-Id":"A"})
    assert ambiguous.status_code==401
    assert ambiguous.json()["detail"]["reason"]=="ambiguous-credentials"


def test_invalid_auth_and_forged_principal_rejected(env):
    assert env.client.get("/probe",headers={"X-Tenant-Id":"A","X-Principal-Id":env.user["email"]}).status_code==403
    assert env.client.get("/probe",headers={"Authorization":"Bearer synthetic-invalid","X-Tenant-Id":"A"}).status_code==401
    assert get(env,tenant="B",headers={"X-Principal-Id":"other@example.com"}).status_code==403


def test_actual_user_effective_handler_cannot_read_foreign_membership(env):
    own=get(env,"/api/xdr/rbac/users/uB/effective","B")
    assert own.status_code==200 and own.json()["data"]["user"]["id"]=="uB"
    foreign=get(env,"/api/xdr/rbac/users/uA/effective","B")
    missing=get(env,"/api/xdr/rbac/users/missing/effective","B")
    assert foreign.status_code==missing.status_code==404 and foreign.json()==missing.json()


def test_disabled_authenticated_principal_fails_closed(env):
    env.user["enabled"]=False
    assert get(env).status_code==403
    assert get(env,"/api/xdr/rbac/me/effective").status_code==403


def test_disabled_role_and_membership_removal_are_immediate(env):
    assert get(env).status_code==200
    env.roles.rows[0]["enabled"]=False
    assert get(env).status_code==403
    env.roles.rows[0]["enabled"]=True;env.user["tenant_ids"]=["B"];env.user.pop("tenant_id")
    assert get(env,tenant="A").status_code==403


def test_platform_designation_does_not_replace_rbac(env):
    env.user["authority_scope"]="PLATFORM"
    assert get(env,tenant="B").status_code==403
    assert get(env,tenant="C").status_code==403  # registered C but no membership
    assert get(env,tenant="A").status_code==200


def test_signed_token_claims_cannot_forge_customer_or_admin_authority(env):
    import jwt
    token=jwt.encode({"sub":env.user["email"],"tenant_id":"C","authority_scope":"PLATFORM","role":"admin"},deps.JWT_SECRET,algorithm="HS256")
    headers={"Authorization":"Bearer "+token,"X-Tenant-Id":"A"}
    assert env.client.get("/probe",headers=headers).status_code==200
    headers["X-Tenant-Id"]="C"
    assert env.client.get("/probe",headers=headers).status_code==403


def test_foreign_membership_mutation_is_denied_without_changes(env):
    env.roles.rows[1]["permissions"].append("users.update")
    before=copy.deepcopy(env.users.rows)
    response=env.client.put("/api/xdr/rbac/users/uA",headers={**env.headers,"X-Tenant-Id":"B"},json={"display_name":"synthetic forbidden change"})
    assert response.status_code==404 and env.users.rows==before


def test_scope_denials_keep_audit_path(env):
    assert get(env,tenant="C").status_code==403
    assert any(row["action"]=="ACCESS_DENIED" and row["resource_kind"]=="tenant_scope" for row in env.audits)


def test_forged_actor_header_never_changes_handler_identity(env):
    response=get(env,"/userscope/uA","A",headers={"X-Principal-Id":"foreign@example.com"})
    assert response.status_code==200 and response.json()=={"id":"uA","tenant":"A"}
