"""
Worker · runs inside a subprocess.

Usage:
    python -m workspace_recovery.tree_worker <BACKEND_DIR> <CORPUS_JSON>

Prints a JSON list to stdout, one entry per corpus sample:
  {"id": ..., "status": "ok" | "error", "response": <full JSON body>, "http_status": <int>, "error": "..."}

Deterministic: no time-of-day, no randomness. Overrides get_current_user so
we do not need a real JWT / DB user.
"""
import json
import os
import sys
import traceback
import types
from pathlib import Path


def _stub_llm_egress() -> None:
    """Neutralize LLM SDK calls so A/B is deterministic (no temperature noise)."""
    # litellm stub
    litellm = types.ModuleType("litellm")

    def _completion(*_a, **_kw):
        return {
            "choices": [{"message": {"content": ""}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            "model": "stub",
        }

    async def _acompletion(*_a, **_kw):
        return _completion()

    litellm.completion = _completion
    litellm.acompletion = _acompletion
    litellm.api_key = ""
    sys.modules["litellm"] = litellm

    # emergentintegrations.llm.chat stub
    ei = types.ModuleType("emergentintegrations")
    ei_llm = types.ModuleType("emergentintegrations.llm")
    ei_chat = types.ModuleType("emergentintegrations.llm.chat")

    class _StubLlmChat:
        def __init__(self, *_a, **_kw):
            pass

        def with_model(self, *_a, **_kw):
            return self

        def with_temperature(self, *_a, **_kw):
            return self

        def with_max_tokens(self, *_a, **_kw):
            return self

        def with_params(self, *_a, **_kw):
            return self

        def with_system_message(self, *_a, **_kw):
            return self

        def with_response_format(self, *_a, **_kw):
            return self

        async def send_message(self, *_a, **_kw):
            return ""

        def __getattr__(self, name):
            # Any unknown builder-style method returns self so chains work.
            def _noop(*_a, **_kw):
                return self
            return _noop

    class _StubUserMessage:
        def __init__(self, *_a, **_kw):
            pass

    ei_chat.LlmChat = _StubLlmChat
    ei_chat.UserMessage = _StubUserMessage
    sys.modules["emergentintegrations"] = ei
    sys.modules["emergentintegrations.llm"] = ei_llm
    sys.modules["emergentintegrations.llm.chat"] = ei_chat


def main() -> int:
    backend_dir = Path(sys.argv[1]).resolve()
    corpus_path = Path(sys.argv[2]).resolve()

    # ── Determinism guards ────────────────────────────────────────
    # 1. Force analysis_mode=fast at the request level (see below), which
    #    already gates the reasoning engine off.
    # 2. Neutralize any LLM egress by pre-emptively stubbing the two
    #    libraries the backend can call — litellm and
    #    emergentintegrations.llm.chat. This makes the A/B deterministic;
    #    LLM temperature would otherwise inject noise unrelated to the
    #    Decode Pipeline behaviour being certified.
    _stub_llm_egress()

    # Wipe any cached modules so a previous tree's imports do not leak.
    for name in list(sys.modules.keys()):
        if name.startswith((
            "routers", "schemas", "deps", "server", "analysis_core",
            "engine", "v2", "timeline", "nivxforge", "core",
            "utils", "storage", "auth", "workspace",
        )):
            del sys.modules[name]

    # Point Python at the target tree ONLY (not /app/backend).
    sys.path[:] = [str(backend_dir)] + [
        p for p in sys.path
        if not p.endswith("/backend")
    ]
    os.chdir(backend_dir)

    # Boot the FastAPI app + auth override.
    try:
        from server import app  # noqa: E402
        from deps import get_current_user  # noqa: E402

        async def _fake_user():
            return {"email": "recovery@nivxray.local", "role": "admin"}

        app.dependency_overrides[get_current_user] = _fake_user

        from fastapi.testclient import TestClient  # noqa: E402
    except Exception:
        print(json.dumps({
            "fatal": True,
            "tree": str(backend_dir),
            "traceback": traceback.format_exc(),
        }))
        return 2

    # Load via the schema-agnostic loader so worker never depends on
    # corpus layout. `corpus_path` overrides the default location so the
    # v1.5.6 baseline tree and the current HEAD read the identical file.
    from workspace_recovery.corpus_loader import load_samples  # noqa: E402
    samples = load_samples(corpus_path)
    results = []
    # `with TestClient(app):` triggers lifespan startup so validate_config +
    # init_database + seed_admin all run — which is what /api/decode/smart
    # needs to reach the DB layer (models_studio.find_matching_recipes).
    try:
        with TestClient(app) as client:
            for sample in samples:
                entry = {"id": sample["id"], "family": sample["family"]}
                try:
                    resp = client.post(
                        "/api/decode/smart",
                        json={"input": sample["input"], "analysis_mode": "fast"},
                    )
                    entry["http_status"] = resp.status_code
                    try:
                        entry["response"] = resp.json()
                        entry["status"] = "ok"
                    except Exception:
                        entry["response"] = {"_raw_text": resp.text}
                        entry["status"] = "non_json"
                except Exception:
                    entry["status"] = "error"
                    entry["error"] = traceback.format_exc()
                results.append(entry)
    except Exception:
        print(json.dumps({
            "fatal": True,
            "tree": str(backend_dir),
            "traceback": traceback.format_exc(),
            "partial_results": results,
        }))
        return 3

    print(json.dumps({"tree": str(backend_dir), "results": results}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
