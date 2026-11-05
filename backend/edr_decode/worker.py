"""Private JSON worker for ProcessDecoder; never execute recovered content."""
from __future__ import annotations

import importlib.abc
import json
import logging
from pathlib import Path
import sys


def main():
    sys.dont_write_bytecode = True
    backend = Path(__file__).resolve().parents[1]
    sys.path[:0] = [str(backend.parent), str(backend)]
    blocked = []

    class Boundary(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname, path=None, target=None):
            if fullname.split(".")[0] in {"deps", "server", "dotenv", "motor", "pymongo", "httpx", "requests"}:
                blocked.append("import:" + fullname)
                raise RuntimeError("shared/network dependency forbidden")

    def audit(event, args):
        if event.startswith("socket.") or event in {"subprocess.Popen", "os.system", "os.fork", "os.posix_spawn"}:
            blocked.append(event)
            raise RuntimeError("network/process operation forbidden")
        if event == "open" and isinstance(args[0], (str, bytes)):
            name = str(args[0])
            if Path(name).name == ".env" or Path(name).name.startswith(".env."):
                blocked.append("environment-file")
                raise RuntimeError("environment file forbidden")

    sys.meta_path.insert(0, Boundary())
    sys.addaudithook(audit)
    payload = sys.stdin.buffer.read(30 * 1024 * 1024 + 1)
    if len(payload) > 30 * 1024 * 1024:
        raise ValueError("request too large")
    request = json.loads(payload)
    mode = request.get("mode", "decode")
    if mode in {"command", "recipe"}:
        from edr_decode.forensics import analyze_request
        report = analyze_request(request)
        if blocked:
            return {"status": "not_ready", "reason": "analysis encountered blocked dependency"}
        return {"status": "complete", "report": report}
    if mode != "decode":
        raise ValueError("unsupported worker mode")
    errors = []

    class Errors(logging.Handler):
        def emit(self, record):
            if record.levelno >= logging.ERROR:
                errors.append(record.getMessage())

    logging.getLogger("nivx.engine.registry").addHandler(Errors())
    from engine.registry import DecoderRegistry
    from engine.models import AnalysisContext, Budget
    from engine.orchestrator import Orchestrator
    from wrapper_archetypes import try_archetypes

    loaded = {p.id for p in DecoderRegistry.all()}
    required = set(request["expected_plugins"])
    if not required or loaded != required or errors or blocked:
        return {"status": "not_ready", "reason": "decoder plugin registration incomplete or unexpected"}
    original = request["command_line"]
    arch = try_archetypes(original)
    decoded_input = (arch or {}).get("output") or original
    report = Orchestrator(AnalysisContext(budget=Budget(**request["budget"]))).run(decoded_input).model_dump()
    if arch and arch.get("output"):
        steps = arch.get("steps") or []
        layers = [{"layer": -(len(steps) - i),
                   "decoder": step.get("op") or arch.get("archetype_id") or "archetype",
                   "confidence": .9, "why": arch.get("archetype_desc") or "Workspace archetype match",
                   "in_len": len(original.encode("utf-8")), "out_len": len(decoded_input.encode("utf-8")),
                   "exec_ms": 0, "preview": decoded_input[:200], "sub_iocs": {},
                   "source": "wrapper_archetype"} for i, step in enumerate(steps)]
        report["trace"] = layers + (report.get("trace") or [])
    if blocked or errors:
        return {"status": "not_ready", "reason": "decode encountered blocked dependency or registration error"}
    return {"status": "complete", "report": report}


if __name__ == "__main__":
    try:
        result = main()
        encoded = json.dumps(result)
        if len(encoded.encode("utf-8")) > 16 * 1024 * 1024:
            result = {"status": "error", "reason": "decoder report exceeds size limit"}
            encoded = json.dumps(result)
        print(encoded)
    except Exception:
        # Do not expose command contents, credentials or import paths in errors.
        print(json.dumps({"status": "error", "reason": "decoder worker failed"}))

