"""
Persistence store · Phase B.

Tenant-scoped connector configurations + checkpoints.  In-process by
default; if `XDR_STATE_DIR` is set, records are also mirrored to disk
so a collector restart doesn't lose configured integrations.

Credentials are stored verbatim inside `config.credentials` — the
caller (route handler) is responsible for redacting them from any
API response.  The disk mirror is chmod 600.
"""
from __future__ import annotations

import json
import os
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime    import datetime, timezone
from typing      import Any, Dict, List, Optional


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ConnectorRecord:
    id:           str
    tenant_id:    str
    source_type:  str      # "rest", "webhook", "syslog", ...
    label:        str
    config:       Dict[str, Any] = field(default_factory=dict)
    created_at:   str = ""
    updated_at:   str = ""
    enabled:      bool = True

    # runtime-only fields (persisted metrics live on the running instance)
    def redacted(self) -> Dict[str, Any]:
        cfg = dict(self.config or {})
        creds = dict(cfg.get("credentials") or {})
        redacted = {k: "***" for k in creds.keys()}
        if redacted:
            cfg["credentials"] = redacted
        return {
            "id":          self.id,
            "tenant_id":   self.tenant_id,
            "source_type": self.source_type,
            "label":       self.label,
            "config":      cfg,
            "created_at":  self.created_at,
            "updated_at":  self.updated_at,
            "enabled":     self.enabled,
        }


class ConnectorStore:
    """Thread-safe connector config store.

    All mutations flush the in-process dict AND (if configured) the
    JSON file at `${XDR_STATE_DIR}/connectors.json`.
    """
    def __init__(self, state_dir: Optional[str] = None) -> None:
        self._lock = threading.RLock()
        self._records: Dict[str, ConnectorRecord] = {}
        self._state_dir = state_dir or os.environ.get("XDR_STATE_DIR")
        self._path      = os.path.join(self._state_dir, "connectors.json") \
                            if self._state_dir else None
        self._load()

    # ── persistence ────────────────────────────────────────────
    def _load(self) -> None:
        if not self._path or not os.path.isfile(self._path):
            return
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for row in data.get("connectors", []):
                r = ConnectorRecord(**row)
                self._records[r.id] = r
        except Exception:                                       # noqa: BLE001
            # Malformed state must not crash boot; log-and-continue.
            pass

    def _flush(self) -> None:
        if not self._path:
            return
        os.makedirs(self._state_dir, exist_ok=True)
        tmp = self._path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"connectors": [asdict(r) for r in self._records.values()]},
                        f, indent=2)
        os.replace(tmp, self._path)
        try:
            os.chmod(self._path, 0o600)
        except OSError:
            pass

    # ── CRUD ───────────────────────────────────────────────────
    def create(self, tenant_id: str, source_type: str, label: str,
                 config: Dict[str, Any]) -> ConnectorRecord:
        with self._lock:
            rid = f"{source_type}-{uuid.uuid4().hex[:8]}"
            now = _utcnow()
            r = ConnectorRecord(id=rid, tenant_id=tenant_id,
                                    source_type=source_type, label=label,
                                    config=config, created_at=now,
                                    updated_at=now, enabled=True)
            self._records[rid] = r
            self._flush()
            return r

    def get(self, cid: str) -> Optional[ConnectorRecord]:
        with self._lock:
            return self._records.get(cid)

    def list(self, tenant_id: Optional[str] = None) -> List[ConnectorRecord]:
        with self._lock:
            if tenant_id is None:
                return list(self._records.values())
            return [r for r in self._records.values() if r.tenant_id == tenant_id]

    def update(self, cid: str, **fields) -> Optional[ConnectorRecord]:
        with self._lock:
            r = self._records.get(cid)
            if not r:
                return None
            for k, v in fields.items():
                if hasattr(r, k):
                    setattr(r, k, v)
            r.updated_at = _utcnow()
            self._flush()
            return r

    def delete(self, cid: str) -> bool:
        with self._lock:
            gone = self._records.pop(cid, None) is not None
            if gone:
                self._flush()
            return gone
