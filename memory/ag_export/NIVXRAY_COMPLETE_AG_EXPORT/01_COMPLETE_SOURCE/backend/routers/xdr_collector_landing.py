"""
NivXRay XDR — Collector Landing (Round 24.95).
==============================================

Owner-locked decision (2026-02-14): the previously standalone
``/app/apps/nivxray-xdr-collector`` collector runtime is landed
INSIDE the main backend so the XDR frontend has a reachable
collector without a second deployment.

Architectural rule (Option C, owner-approved):
  • HTTP transports (REST poller · webhook receiver · connector
    CRUD · outbox · ingest health) land here, mounted under
    ``/api/xdr/collector/*``.
  • Syslog UDP stays behind — customers who need syslog run the
    standalone collector as an on-prem forwarder that POSTs into
    this landed collector's webhook receiver.  The standalone
    process is UNCHANGED and remains independently deployable.
  • ``VITE_XDR_COLLECTOR_URL`` becomes an *override* on the
    frontend, not a *requirement* — the default is the main
    backend.

Boundary invariants (must not drift):
  • This module NEVER decides a verdict, correlation, or
    investigation intelligence.  Its sole job is transport →
    outbox → (later, Round 26) canonical evidence writer.
  • Credentials in `config.credentials` are stored on disk under
    ``XDR_STATE_DIR`` (chmod 600); the Round 25b vault will
    replace this with envelope-encrypted at-rest storage.
  • Fails HONESTLY: if `/app/apps/nivxray-xdr-collector` is
    absent or broken, the landing raises during startup so the
    Integration Control Center continues to say "collector not
    wired" — never fakes a healthy state.

Why sys.path import instead of copy:
  The standalone service is a shipping artefact (Dockerfile,
  DEPLOY.md, its own tests).  Duplicating its code inside
  /app/backend would create a divergence surface.  A single
  reference implementation is the safer contract.
"""
from __future__ import annotations

import logging
import os
import sys
from typing import Optional

from fastapi import FastAPI

log = logging.getLogger("nivxray.xdr.collector.landing")

_COLLECTOR_ROOT = "/app/apps/nivxray-xdr-collector"


def _ensure_importable() -> bool:
    """Add the collector repo to sys.path if the package layout is
    still there.  Returns True on success, False if the standalone
    directory was removed / renamed."""
    if not os.path.isdir(os.path.join(_COLLECTOR_ROOT, "framework")):
        log.warning("collector landing: standalone package missing at %s",
                        _COLLECTOR_ROOT)
        return False
    if _COLLECTOR_ROOT not in sys.path:
        sys.path.insert(0, _COLLECTOR_ROOT)
    return True


def attach_collector_landing(app: FastAPI,
                                 prefix: str = "/api/xdr/collector") -> bool:
    """Mount the landed collector on ``app`` under ``prefix``.

    Wires app.state.{registry, store, runtime, instances} on startup
    and shuts them down cleanly on app teardown.  Returns True on
    success, False if the landing was skipped (dir missing).
    """
    if not _ensure_importable():
        return False

    # Imports resolved after sys.path is amended.
    from framework.registry     import ConnectorRegistry             # noqa: E402
    from framework.runtime      import CollectorRuntime              # noqa: E402
    from framework.store        import ConnectorStore                # noqa: E402
    from framework.rest_poller  import RestPollerConnector           # noqa: E402
    from framework.webhook      import WebhookConnector              # noqa: E402
    from framework.syslog       import SyslogConnector               # noqa: E402

    from routes.connectors       import router as connectors_router        # noqa: E402
    from routes.collectors       import router as collectors_router        # noqa: E402
    from routes.telemetry_health import router as telemetry_health_router  # noqa: E402
    from routes.data_sources     import router as data_sources_router      # noqa: E402
    from routes.webhooks         import router as webhooks_router          # noqa: E402
    from routes.outbox           import router as outbox_router            # noqa: E402
    from routes.preflight        import router as preflight_router         # noqa: E402

    class_by_type = {
        "rest":    RestPollerConnector,
        "webhook": WebhookConnector,
        "syslog":  SyslogConnector,
    }

    # ── Startup: build state + rehydrate persisted connectors ────
    @app.on_event("startup")
    async def _collector_landing_startup():
        # Persistent state dir defaults to a backend-local path so a
        # pod restart preserves configured integrations.
        state_dir = os.environ.get("XDR_STATE_DIR", "/app/backend/xdr_state")
        os.makedirs(state_dir, exist_ok=True)
        os.environ.setdefault("XDR_STATE_DIR", state_dir)

        app.state.registry  = ConnectorRegistry()
        app.state.store     = ConnectorStore(state_dir=state_dir)
        app.state.runtime   = CollectorRuntime()
        app.state.instances = {}

        rehydrated = 0
        for rec in app.state.store.list():
            cls = class_by_type.get(rec.source_type)
            if not cls:
                continue
            try:
                inst = cls(tenant_id=rec.tenant_id, config=rec.config,
                             identity=rec.id)
                app.state.instances[rec.id] = inst
                app.state.registry.register_instance(inst)
                rehydrated += 1
                # Auto-start unless disabled.  Syslog binds a UDP
                # port and will fail honestly inside a pod that
                # doesn't expose UDP — that's the intended
                # Option-C signal for the customer to run the
                # standalone on-prem forwarder.
                if rec.enabled and os.environ.get(
                        "XDR_AUTO_START_CONNECTORS", "1") == "1":
                    try:
                        await app.state.runtime.start(inst)
                    except Exception as e:                          # noqa: BLE001
                        log.warning("collector landing: auto-start "
                                          "%s failed (%s)", rec.id, e)
            except Exception as e:                                  # noqa: BLE001
                log.warning("collector landing: rehydrate %s failed (%s)",
                                rec.id, e)

        # Delivery worker: intentionally NOT started here.  The
        # landed collector delivers evidence to the SAME process
        # via Round 26's canonical-evidence writer — an internal
        # call, not an HTTP round-trip.  Until Round 26 lands, the
        # outbox accumulates and the ingest state reports honestly
        # as ``not_configured``.
        log.info("collector landing: ready · state_dir=%s · "
                    "connectors_rehydrated=%d", state_dir, rehydrated)

    @app.on_event("shutdown")
    async def _collector_landing_shutdown():
        runtime = getattr(app.state, "runtime", None)
        instances = getattr(app.state, "instances", {})
        if runtime is None:
            return
        for inst in list(instances.values()):
            try:
                await runtime.stop(inst)
            except Exception:                                        # noqa: BLE001
                pass
        try:
            runtime.outbox.close()
        except Exception:                                            # noqa: BLE001
            pass

    # ── Mount the seven collector routers under the landing prefix.
    app.include_router(connectors_router,       prefix=prefix)
    app.include_router(collectors_router,       prefix=prefix)
    app.include_router(telemetry_health_router, prefix=prefix)
    app.include_router(data_sources_router,     prefix=prefix)
    app.include_router(webhooks_router,         prefix=prefix)
    app.include_router(outbox_router,           prefix=prefix)
    app.include_router(preflight_router,        prefix=prefix)

    # Tiny liveness echo so the frontend can distinguish "landed"
    # from "not deployed" cheaply.  Never touches Mongo.
    @app.get(f"{prefix}/landing")
    def _landing_receipt():
        return {
            "landed":  True,
            "prefix":  prefix,
            "phase":   "24.95",
            "mode":    "in-process",
            "syslog":  "on-prem-forwarder-only",
            "docs":    ("Round 24.95 · HTTP transports landed in "
                          "main backend; syslog stays on standalone "
                          "forwarder."),
        }

    log.info("collector landing: mounted at %s", prefix)
    return True
