"""The complete NivXForge EDR capability honesty baseline.

Owner decision 5A: grade **every** capability in the directive across all
three planes BEFORE implementation expands further, so every future wave
can be measured against a permanent machine-readable baseline.

Grading rule, owner-locked and applied to every row below:

    No capability is considered implemented merely because a route, UI
    component, stub, simulator, or contract exists.

Where a row claims more than the repo can prove, `Capability` downgrades
it automatically and records `downgrade_reason`. Nothing here is graded
from memory: every non-ABSENT status carries an `evidence_reference` to a
file, route, test or test report in this repository.
"""
from __future__ import annotations

from .model import (Capability, ComponentStatus as CS, FeatureState as FS,
                    GapClass as GC, Plane, SensorCapability)

_A, _P, _S, _N, _NA = (CS.ABSENT, CS.PRESENT, CS.STUB, CS.PARTIAL,
                       CS.NOT_APPLICABLE)


def _cap(cid, plane, domain, name, desc, *, state=FS.NOT_IMPLEMENTED,
         gap=GC.NONE, contract=_A, backend=_A, ui=_A, telemetry=_A,
         driver=_NA, test=_A, e2e=_A, ev=None, note=None, wave=None
         ) -> Capability:
    return Capability(
        capability_id=cid, plane=plane, domain=domain, name=name,
        description=desc, declared_state=state, gap_class=gap,
        contract_status=contract, backend_status=backend, ui_status=ui,
        telemetry_status=telemetry, control_driver_status=driver,
        test_status=test, e2e_status=e2e, evidence_reference=ev,
        honest_note=note, wave=wave)


# ══ PLANE A · ENDPOINT AGENT ══════════════════════════════════════
# Directive §4: the backend cannot pretend to be a kernel sensor. No
# NivXForge agent exists on any platform yet, so every collection row is
# NOT_IMPLEMENTED with TELEMETRY_MISSING. The Wave 0 contracts now exist
# for all of them, which is the honest difference between "we have not
# built it" and "we do not know what it should produce".

_AGENT_MATRIX = {
    "WINDOWS": ["process", "file", "network", "registry", "service",
                "driver", "persistence", "user_session", "usb", "memory",
                "security_controls"],
    "MACOS": ["process", "file", "network", "endpoint_security",
              "persistence", "user_session", "device"],
    "LINUX": ["process", "file", "network", "ebpf", "persistence",
              "user_session", "container"],
}

_CONTRACTED = {"process", "file", "network", "registry", "user_session",
               "persistence", "usb", "service"}

#: P0-B · domains the REAL Linux sensor collects from live /proc today.
#: These are the only agent rows in the whole matrix that are not
#: aspirational.
_LINUX_REAL = {"process", "file", "network"}

AGENT_CAPABILITIES: list[Capability] = [
    _cap(f"agent.{plat.lower()}.{dom}", Plane.AGENT, f"{plat} sensor",
         f"{plat} {dom.replace('_', ' ')} telemetry",
         f"Endpoint-resident collection of {dom.replace('_', ' ')} events "
         f"on {plat}.",
         state=(FS.REAL_ENDPOINT_VALIDATED
                if (plat == "LINUX" and dom in _LINUX_REAL)
                else FS.CONTRACT_DEFINED if dom in _CONTRACTED
                else FS.NOT_IMPLEMENTED),
         gap=(GC.NONE if (plat == "LINUX" and dom in _LINUX_REAL)
              else GC.TELEMETRY_MISSING),
         contract=(_P if dom in _CONTRACTED else _A),
         backend=(_P if (plat == "LINUX" and dom in _LINUX_REAL) else _A),
         telemetry=(_P if (plat == "LINUX" and dom in _LINUX_REAL) else _A),
         test=(_P if (plat == "LINUX" and dom in _LINUX_REAL) else _A),
         e2e=(_P if (plat == "LINUX" and dom in _LINUX_REAL) else _A),
         ev=("agents/nivxforge-linux/nivxforge_sensor.py · "
             "tests/edr/test_p0_b_linux_sensor.py"
             if (plat == "LINUX" and dom in _LINUX_REAL)
             else "backend/edr_plane/contracts/telemetry.py"
             if dom in _CONTRACTED else None),
         note=("REAL: collected from live /proc on an enrolled endpoint and "
               "proven end-to-end into Device Trajectory. Honest limits — "
               "process EXIT is not observed (polling cannot distinguish "
               "exit from a missed scan), the file WRITER is not observed, "
               "and processes living inside one poll interval are missed "
               "entirely."
               if (plat == "LINUX" and dom in _LINUX_REAL)
               else "No NivXForge agent is installed on this platform. The "
                    "canonical shape is contracted; nothing produces it."),
         wave=("P0-B · DONE" if (plat == "LINUX" and dom in _LINUX_REAL)
               else "P0-B" if plat == "LINUX" else "P0-I"))
    for plat, doms in _AGENT_MATRIX.items() for dom in doms
] + [
    _cap("agent.identity", Plane.AGENT, "agent core",
         "Agent-side endpoint identity",
         "Agent derives and reports its durable endpoint identity "
         "(hardware id, machine guid) for enrolment.",
         state=FS.CONTRACT_DEFINED, gap=GC.TELEMETRY_MISSING, contract=_P,
         ev="backend/edr_plane/contracts/identity.py::EndpointIdentity",
         wave="P0-A.2"),
    _cap("agent.enrollment", Plane.AGENT, "agent core",
         "Agent-side enrolment",
         "Agent presents a one-time bootstrap token and stores the issued "
         "durable per-agent credential.",
         contract=_P,
         ev="backend/edr_plane/enrollment/store.py::enroll · "
            "POST /api/edr/agent/enroll · "
            "agents/nivxforge-linux/nivxforge_sensor.py::enrol",
         state=FS.REAL_ENDPOINT_VALIDATED, backend=_P, telemetry=_P,
         test=_P, e2e=_P, gap=GC.NONE,
         note="The real Linux sensor enrols with a one-time token and "
              "stores its durable credential 0600 on disk. Proven on this "
              "container: endpoint_id is minted by the PLATFORM from "
              "durable machine attributes; the sensor never proposes one.",
         wave="P0-B · DONE"),
    _cap("agent.durable_queue", Plane.AGENT, "agent core",
         "Local durable queue / buffer",
         "On-endpoint append-only buffer so a connectivity loss replays "
         "instead of silently losing evidence.",
         state=FS.REAL_ENDPOINT_VALIDATED, backend=_P, telemetry=_P,
         test=_P, e2e=_P, gap=GC.NONE, contract=_P,
         ev="agents/nivxforge-linux/nivxforge_sensor.py::_drain · _enqueue",
         note="ON-ENDPOINT append-only JSONL outbox with an fsync and a "
              "byte-exact offset advanced only after a confirmed accept. "
              "Proven: with the platform unreachable 149 events were HELD "
              "(offset frozen, queue grown) and replayed in full on "
              "recovery. A defect found and fixed during that proof: "
              "text-mode readline()+tell() over-advanced the offset and "
              "re-sent the queue — now binary reads with an accumulated "
              "offset.",
         wave="P0-C · DONE"),
    _cap("agent.secure_transport", Plane.AGENT, "agent core",
         "Secure telemetry transport",
         "Authenticated, pluggable transport from agent to ingestion "
         "gateway; mTLS must drop in without touching identity or envelope.",
         state=FS.REAL_ENDPOINT_VALIDATED, backend=_P, telemetry=_P,
         test=_P, e2e=_P, gap=GC.NONE, contract=_P,
         ev="backend/edr_plane/enrollment/transport.py · "
            "POST /api/edr/agent/telemetry",
         note="The sensor authenticates with a short-lived scoped session "
              "and re-opens it automatically on 401/403 without dropping "
              "queued evidence. mTLS remains a reserved, honestly "
              "unregistered transport.",
         wave="P0-C · DONE"),
    _cap("agent.heartbeat", Plane.AGENT, "agent core",
         "Agent heartbeat / lifecycle reporting",
         "Agent reports lifecycle state so agent_lifecycle is evidence "
         "rather than inference.",
         state=FS.CONTRACT_DEFINED, gap=GC.TELEMETRY_MISSING, contract=_P,
         ev="backend/services/edr/endpoint_health.py::resolve_agent_lifecycle",
         note="The resolver already returns NO_AGENT for every endpoint — "
              "correctly, because no agent heartbeats.",
         wave="P0-A.2"),
    _cap("agent.response_executor", Plane.AGENT, "agent core",
         "On-endpoint response executor",
         "Executes isolate / kill / quarantine / scan / fetch and emits "
         "verification telemetry.",
         gap=GC.CONTROL_DRIVER_MISSING, driver=_A, wave="P0-H"),
]


# ══ PLANE B · EDR CLOUD / BACKEND ═════════════════════════════════

PIPELINE_CAPABILITIES: list[Capability] = [
    _cap("backend.collection", Plane.BACKEND, "pipeline",
         "Telemetry collection", "Acquire -> Parse -> Normalize -> Deliver "
         "collector service with a durable outbox.",
         state=FS.END_TO_END_VALIDATED, backend=_P, telemetry=_N, test=_P,
         e2e=_P, contract=_P,
         ev="apps/nivxray-xdr-collector · scripts/p1_10_live_proof.py · "
            "test_reports/iteration_85.json",
         note="Proven with real CEF/LEEF on UDP 5514. Syslog only; webhook "
              "and REST poller still deliver native payloads."),
    _cap("backend.parser", Plane.BACKEND, "pipeline",
         "Parser / DSM registry", "Source-specific parsers registered as "
         "DSMs; core re-parses the verbatim raw line.",
         state=FS.GOLDEN_CORPUS_VALIDATED, backend=_P, telemetry=_N,
         test=_P, e2e=_P, contract=_P,
         ev="backend/detection_content/telemetry/cef_leef_dsm.py · "
            "tests/edr/test_p1_10_cef_leef_dsm.py (10 tests)",
         note="6 DSMs registered. No SENSOR DSM exists yet — that is P0-D."),
    _cap("backend.normalizer", Plane.BACKEND, "pipeline",
         "Normalizer", "Canonical event -> CES -> CEM observation.",
         state=FS.BACKEND_IMPLEMENTED, backend=_P, telemetry=_N, test=_P,
         contract=_P, ev="backend/v2/ingestion/telemetry_bridge.py"),
    _cap("backend.raw_events", Plane.BACKEND, "pipeline",
         "Immutable raw-event substrate",
         "Append-only edr_raw_events with parser/normalizer/detection/"
         "analysis/verdict version stamps. Nothing downstream may overwrite "
         "the original event.",
         state=FS.END_TO_END_VALIDATED, backend=_P, contract=_P, test=_P,
         telemetry=_N, e2e=_P,
         ev="backend/edr_plane/raw_events.py · "
            "tests/edr/test_wave0_raw_events.py · "
            "POST /api/edr/agent/telemetry",
         note="Directive §4 correction: v2_shadow_observations alone was not "
              "a sufficient substrate. As of P0-A.2 this IS the live write "
              "path for authenticated agent telemetry, and every event "
              "carries the endpoint/credential/session that produced it. "
              "Legacy collector telemetry still lands as shadow "
              "observations (P0-D).",
         wave="Wave 0 · P0-A.2"),
    _cap("backend.replay", Plane.BACKEND, "pipeline",
         "Retrospective replay",
         "Re-reason retained raw telemetry after a parser, normalizer, "
         "detection or intelligence improvement, at a new "
         "replay_generation.",
         state=FS.BACKEND_IMPLEMENTED, backend=_N, contract=_P, test=_P,
         ev="backend/edr_plane/raw_events.py::replay_candidates",
         note="Selection and generation stamping exist; driving the full "
              "pipeline over a replay set is not wired.",
         wave="Wave 0"),
    _cap("backend.canonical_evidence", Plane.BACKEND, "pipeline",
         "Canonical endpoint evidence",
         "The single shape the detection, reasoning and console layers "
         "consume.",
         state=FS.REAL_ENDPOINT_VALIDATED, backend=_P, contract=_P, test=_P,
         telemetry=_P, e2e=_P,
         ev="backend/edr_plane/canonical_bridge.py · "
            "tests/edr/test_p0_b_linux_sensor.py",
         note="P0-D: the sensor DSM produces the same canonical shape the "
              "CEF/LEEF DSM produces and hands off to the EXISTING "
              "telemetry_bridge — no parallel evidence model and no second "
              "reasoning engine. A parse failure appends a PARSER_FAILED "
              "derivation and leaves the raw bytes replayable.",
         wave="Wave 0 · P0-D"),
    _cap("backend.endpoint_detection", Plane.BACKEND, "detection",
         "Endpoint detection via the authoritative XDR fabric",
         "Real endpoint evidence is evaluated by the SAME detection "
         "engine, IUE, ICE and VEEE chain every other source uses.",
         state=FS.REAL_ENDPOINT_VALIDATED, backend=_P, ui=_P, telemetry=_P,
         test=_P, e2e=_P, contract=_P, gap=GC.NONE,
         ev="detection_content/telemetry/nivxforge_sensor_dsm.py · "
            "detection_content/library/rules_edr_linux.py · "
            "GET /api/edr/endpoint-detections · "
            "tests/edr/test_p0_f_endpoint_detection.py · "
            "scripts/p0_f_detection_proof.py",
         note="P0-F + P0-F.1: the endpoint plane CONSUMES the fabric — it "
              "owns no engine, registry or rule model. Proven on real "
              "behaviour executed on this host: 5 Linux rules fired with "
              "full raw_id → canonical_event_id → rule provenance, benign "
              "controls did not alert, and a CRITICAL detection now "
              "reaches MALICIOUS/80 and a REAL incident "
              "(INC000000227-class) through the UNCHANGED VEEE gate. The "
              "root cause was that IUE only read a VENDOR severity band, "
              "which a sensor never supplies — no threshold was moved. "
              "STILL A GAP: the 5-second poll means a command that starts "
              "and exits between scans is never evaluated at all, and "
              "repeated malicious behaviour currently opens one incident "
              "per observed process rather than one per campaign.",
         wave="P0-F · DONE"),
    _cap("backend.activity_identity", Plane.BACKEND, "pipeline",
         "One real activity → one piece of evidence",
         "A re-observation of the same process, connection or file state is "
         "linked to the evidence that already represents it instead of "
         "creating a second row.",
         state=FS.REAL_ENDPOINT_VALIDATED, backend=_P, contract=_P, test=_P,
         telemetry=_P, e2e=_P, gap=GC.NONE,
         ev="backend/edr_plane/canonical_bridge.py::activity_identity · "
            "tests/edr/test_p0_b_linux_sensor.py::"
            "test_a_re_observed_process_does_not_become_second_evidence · "
            "scripts/p0_b_sensor_proof.py",
         note="Found and fixed during the P0-B/P0-D acceptance proof: a "
              "sensor restart re-reported the running process table, so ONE "
              "real process was held as up to ten evidence rows and read as "
              "ten starts that never happened. The raw bytes of every "
              "delivery are still retained immutably and the duplicate is "
              "recorded as a DUPLICATE_OBSERVATION_OF_KNOWN_ACTIVITY "
              "derivation — nothing is discarded, it is simply not counted "
              "twice.",
         wave="P0-D · DONE"),
    _cap("backend.evidence_store", Plane.BACKEND, "pipeline",
         "Endpoint / evidence store",
         "Durable persistence of observations and canonical evidence.",
         state=FS.BACKEND_IMPLEMENTED, backend=_P, telemetry=_N, test=_P,
         ev="v2_shadow_observations · xdr_canonical_evidence"),
    _cap("backend.search_index", Plane.BACKEND, "pipeline",
         "Endpoint search index",
         "Fleet-wide search across processes, files, hashes and network "
         "peers.",
         gap=GC.TELEMETRY_MISSING,
         note="Mongo queries exist per surface; there is no endpoint search "
              "index.", wave="Wave 10"),
    _cap("backend.ingestion_gateway", Plane.BACKEND, "pipeline",
         "EDR ingestion gateway",
         "Authenticated ingest boundary with tenant isolation and refused-"
         "evidence recording.",
         state=FS.END_TO_END_VALIDATED, backend=_P, telemetry=_N, test=_P,
         contract=_P, e2e=_P,
         ev="backend/routers/edr_enrollment.py · "
            "backend/edr_plane/enrollment/transport.py · "
            "tests/edr/test_p0_a2_enrollment.py (29) · "
            "tests/edr/test_cross_tenant.py (20)",
         note="P0-A.2: /api/edr/agent/telemetry is authenticated per-agent "
              "and refuses unenrolled or revoked agents with 401/403 plus a "
              "security signal. The legacy /api/xdr/ingest/telemetry path "
              "remains tenant-isolated but NOT per-agent authenticated.",
         wave="P0-A.2 · DONE"),
    _cap("backend.telemetry_health", Plane.BACKEND, "pipeline",
         "Telemetry health (2 dimensions)",
         "Agent lifecycle x telemetry health, computed and never collapsed.",
         state=FS.GOLDEN_CORPUS_VALIDATED, backend=_P, ui=_P, telemetry=_N,
         test=_P, e2e=_P, contract=_P,
         ev="backend/services/edr/endpoint_health.py · "
            "tests/edr/test_p0_a1_endpoint_health.py (13) · "
            "test_reports/iteration_88.json (100% frontend)",
         note="Closed as P0-A.1. Cannot reach REAL_ENDPOINT_VALIDATED "
              "because no real agent exists to report a lifecycle.",
         wave="P0-A.1 · DONE"),
    _cap("backend.enrollment", Plane.BACKEND, "identity & trust",
         "Endpoint enrolment (one-time token)",
         "Admin mints a short-TTL single-use token; the agent presents it "
         "once; the platform mints the endpoint_id from durable machine "
         "attributes and issues the durable credential; the token is burned "
         "atomically.",
         state=FS.END_TO_END_VALIDATED, backend=_P, ui=_P, contract=_P,
         test=_P, e2e=_P, telemetry=_N,
         ev="backend/edr_plane/enrollment/store.py · "
            "tests/edr/test_p0_a2_enrollment.py (29 tests incl. 25- and "
            "50-way concurrent single-use proofs)",
         note="endpoint_id is minted BY THE PLATFORM (hardware > machine "
              "guid > device_iid > hostname) and never accepted from the "
              "agent. Token failure modes are deliberately "
              "indistinguishable so the error is not an oracle.",
         wave="P0-A.2 · DONE"),
    _cap("backend.agent_auth", Plane.BACKEND, "identity & trust",
         "Agent credential + scoped session",
         "Opaque durable per-agent credential (HMAC-SHA-256 keyed digest at "
         "rest, never a JWT, never retrievable) exchanged for a short-lived "
         "endpoint-scoped session token used on continuous telemetry.",
         state=FS.END_TO_END_VALIDATED, backend=_P, ui=_P, contract=_P,
         test=_P, e2e=_P, telemetry=_N,
         ev="backend/edr_plane/enrollment/security.py · "
            "backend/edr_plane/enrollment/store.py::resolve_session · "
            "tests/edr/test_p0_a2_enrollment.py",
         note="auth_epoch invalidates an in-flight, still-unexpired session "
              "the instant its credential is revoked or rotated — a "
              "guarantee that does not depend on a second write "
              "succeeding.",
         wave="P0-A.2 · DONE"),
    _cap("backend.transport_boundary", Plane.BACKEND, "identity & trust",
         "Pluggable transport / auth boundary",
         "Endpoint Identity != Authentication Mechanism != Transport != "
         "Telemetry Envelope. One module knows a bearer token exists; mTLS "
         "replaces it without touching identity, envelope or ingestion.",
         state=FS.BACKEND_IMPLEMENTED, backend=_P, contract=_P, test=_P,
         telemetry=_N,
         ev="backend/edr_plane/enrollment/transport.py::ACTIVE_TRANSPORT",
         note="mTLS is an explicit NOT-REGISTERED stub returning 501 rather "
              "than an absent seam — it never silently falls back to "
              "bearer, because an operator believing mTLS is enforced when "
              "it is not is worse than no mTLS.",
         wave="P0-A.2 · DONE"),
    _cap("backend.rejected_sensor_signal", Plane.BACKEND, "identity & trust",
         "Rejected sensor alarm",
         "Every refused ingest attempt is rejected 401/403 AND recorded as "
         "a security signal with tenant, source IP, credential fingerprint, "
         "timestamp, reason, request id and resolvable endpoint — never "
         "silently dropped, never eligible to become endpoint evidence.",
         state=FS.END_TO_END_VALIDATED, backend=_P, ui=_P, contract=_P,
         test=_P, e2e=_P, telemetry=_N,
         ev="backend/edr_plane/enrollment/rejection.py · "
            "GET /api/edr/enrollment/rejections · "
            "tests/edr/test_p0_a2_enrollment.py",
         note="Stored in edr_rejected_telemetry, which no evidence, "
              "trajectory, detection or verdict path queries — the "
              "isolation is structural. A revoked agent still transmitting "
              "escalates to HIGH.",
         wave="P0-A.2 · DONE"),
    _cap("backend.capability_registry", Plane.BACKEND, "governance",
         "Capability Registry + API",
         "Machine-readable truth authority: feature state, gap class and "
         "evidence reference per capability, served to the console so the "
         "UI cannot claim what the registry denies.",
         state=FS.BACKEND_IMPLEMENTED, backend=_P, contract=_P, test=_P,
         ev="backend/edr_plane/capability/ · GET /api/edr/wave0/capabilities",
         wave="Wave 0"),
    _cap("backend.sensor_capability_registry", Plane.BACKEND, "governance",
         "Sensor Capability Registry",
         "Per-sensor declaration of collected activities, supported fields "
         "and executable response actions, so an unsupported field resolves "
         "NOT_SUPPORTED rather than NOT_OBSERVED.",
         state=FS.CONTRACT_DEFINED, contract=_P, test=_P,
         ev="backend/edr_plane/capability/model.py::SensorCapability",
         note="Zero sensors registered — correctly, since none exist.",
         wave="Wave 0"),
]

REASONING_CAPABILITIES: list[Capability] = [
    _cap(f"backend.reasoning.{k}", Plane.BACKEND, "reasoning fabric", n, d,
         state=FS.OPERATIONAL, backend=_P, telemetry=_N, test=_P, e2e=_P,
         contract=_P, ev=ev,
         note="Authoritative NivXRay engine. REUSED by NivXForge EDR; "
              "duplicating it is forbidden (directive §3).")
    for k, n, d, ev in [
        ("iue", "IUE", "Intent / understanding extraction over canonical "
         "evidence.", "backend/detection_content/xdr_iue.py"),
        ("ice", "ICE", "Correlation of signals into evidence sets.",
         "backend/detection_content/xdr_ice.py"),
        ("ikg", "IKG", "Knowledge-graph binding of entities and relations.",
         "backend/detection_content/xdr_pipeline.py"),
        ("veee", "VEEE", "Evidence-weighted verdict scoring with caps.",
         "backend/detection_content/xdr_pipeline.py::veee_compute"),
        ("verdict", "Verdict engine", "Final verdict with sufficiency.",
         "backend/detection_content/xdr_pipeline.py"),
        ("storyline", "Storyline / attack story",
         "Narrative assembly from correlated evidence.",
         "backend/routers/incident_summary.py"),
        ("security_state", "Security State",
         "Reachability, causality and counterfactual state.",
         "backend/security_state/routers.py (14 endpoints)"),
        ("decoder", "Decoder / DDO",
         "Deterministic decode orchestrator, 14 codecs.",
         "backend/services/decoder/orchestrator.py"),
    ]
]

_DETECTION_FABRIC = [
    ("behavioral", "Behavioral detection", FS.NOT_IMPLEMENTED, _A,
     GC.TELEMETRY_MISSING, None,
     "Requires process/file/network endpoint telemetry that does not exist."),
    ("heuristic", "Heuristic detection", FS.NOT_IMPLEMENTED, _A,
     GC.TELEMETRY_MISSING, None, None),
    ("ioc_ti", "IOC / threat-intel detection", FS.BACKEND_IMPLEMENTED, _P,
     GC.TELEMETRY_MISSING, "backend/services/die/ioc_semantic.py",
     "IOC extraction and matching operate on the evidence we have."),
    ("hash", "Hash detection", FS.BACKEND_IMPLEMENTED, _N,
     GC.TELEMETRY_MISSING, "backend/routers/edr.py::file_trajectory",
     "Hash keys are honoured, but content_digests_available is false — a "
     "SHA-256 query degrades to a name query and says so."),
    ("signature", "Signature detection (OpenIOC / ClamAV / YARA)",
     FS.NOT_IMPLEMENTED, _A, GC.TELEMETRY_MISSING, None, None),
    ("file_property", "File-property detection", FS.NOT_IMPLEMENTED, _A,
     GC.TELEMETRY_MISSING, None, None),
    ("pe_artifact", "PE / artifact detection", FS.BACKEND_IMPLEMENTED, _P,
     GC.TELEMETRY_MISSING, "backend/services/analyzers/pe.py",
     "Static analyzer exists; no endpoint artifact reaches it."),
    ("script", "Script detection", FS.BACKEND_IMPLEMENTED, _P,
     GC.NONE, "backend/services/decoder/powershell.py",
     "PowerShell semantic reconstruction is operational on submitted "
     "command lines."),
    ("network", "Network detection", FS.BACKEND_IMPLEMENTED, _N,
     GC.TELEMETRY_MISSING, "backend/detection_content/xdr_ice.py", None),
    ("sequence", "Sequence detection", FS.NOT_IMPLEMENTED, _A,
     GC.TELEMETRY_MISSING, None, None),
    ("correlation", "Correlation detection", FS.OPERATIONAL, _P, GC.NONE,
     "backend/detection_content/xdr_spread_watchlist.py · "
     "tests/edr/test_p1_10a_spread_watchlist.py (24 tests) · "
     "scripts/p1_10a_spread_proof.py · test_reports/iteration_86.json",
     "Cross-endpoint spread correlation is shipped and proven."),
    ("memory_injection", "Memory / injection detection", FS.NOT_IMPLEMENTED,
     _A, GC.TELEMETRY_MISSING, None, None),
    ("persistence", "Persistence detection", FS.NOT_IMPLEMENTED, _A,
     GC.TELEMETRY_MISSING, None, None),
    ("custom", "Custom detection engine", FS.BACKEND_IMPLEMENTED, _P,
     GC.NONE, "backend/routers/content_supply_chain.py",
     "Rule studio and detection registry exist."),
    ("content_fabric", "NivXRay detection content fabric",
     FS.BACKEND_IMPLEMENTED, _P, GC.NONE,
     "backend/routers/truth_inventory.py::detection_inventory",
     "Cardinality is reported from live runtime, never anchored to a "
     "remembered integer."),
]

DETECTION_CAPABILITIES: list[Capability] = [
    _cap(f"backend.detection.{k}", Plane.BACKEND, "detection fabric", n,
         f"{n} capability of the detection fabric. A match is an "
         f"observation, never a verdict (directive §9.5).",
         state=st, backend=be, gap=gap, telemetry=_N if be != _A else _A,
         test=_P if ev else _A, contract=_P, ev=ev, note=note,
         e2e=_P if ev and ("proof" in ev or "iteration" in ev) else _A)
    for k, n, st, be, gap, ev, note in _DETECTION_FABRIC
]

CONTROL_CAPABILITIES: list[Capability] = [
    _cap("backend.control.policy_engine", Plane.BACKEND, "control fabric",
         "Policy engine (AUDIT / PROTECT / PREVENT)",
         "Evaluates rule, detection type, endpoint, group, OS, user, file, "
         "disposition, confidence, evidence sufficiency, security state, "
         "policy mode and exceptions between detection and enforcement.",
         state=FS.CONTRACT_DEFINED, contract=_P, test=_P,
         ev="backend/edr_plane/contracts/response.py::PolicyMode",
         gap=GC.CONTROL_DRIVER_MISSING, driver=_A,
         note="Policy modes are contracted; no policy plane is bound to any "
              "endpoint or group.", wave="Wave 6"),
    _cap("backend.control.playbook_engine", Plane.BACKEND, "control fabric",
         "Playbook engine",
         "Enrichment -> decision -> escalation -> response -> verification. "
         "Detection -> Playbook -> Action -> Verification, never "
         "detection -> blind execution.",
         state=FS.NOT_IMPLEMENTED, ui=_P, gap=GC.UI_ONLY,
         ev="apps/nivxray-xdr/src/xdr/pages/XdrPlaybooksPage.jsx",
         note="Playbook UI exists in the XDR shell. No EDR playbook "
              "execution engine exists.", wave="Wave 6"),
    _cap("backend.control.response_framework", Plane.BACKEND,
         "control fabric", "Response command / result lifecycle",
         "The §10 loop as enforced state machine. Only VERIFIED is a "
         "success, and verification requires endpoint evidence.",
         state=FS.BACKEND_IMPLEMENTED, backend=_P, contract=_P, test=_P,
         driver=_A, gap=GC.CONTROL_DRIVER_MISSING,
         ev="backend/edr_plane/contracts/response.py · "
            "tests/edr/test_wave0_contracts.py",
         note="The lifecycle refuses to reach VERIFIED without evidence. No "
              "response DRIVER is registered, so every real action returns "
              "DRIVER_NOT_REGISTERED.", wave="Wave 0"),
    _cap("backend.control.response_decision", Plane.BACKEND,
         "control fabric", "Response decision surface",
         "Advertises available actions with honest capability flags.",
         state=FS.BACKEND_IMPLEMENTED, backend=_P, test=_P, contract=_P,
         driver=_A, gap=GC.CONTROL_DRIVER_MISSING,
         ev="backend/detection_content/xdr_response_decision.py:302 · "
            "GET /api/response/actions",
         note="Returns CAPABILITY_UNAVAILABLE honestly for 13 actions."),
    _cap("backend.control.verification", Plane.BACKEND, "control fabric",
         "Response verification",
         "Confirms an action took effect from endpoint telemetry and closes "
         "the loop into security state.",
         state=FS.CONTRACT_DEFINED, contract=_P, test=_P, driver=_A,
         gap=GC.TELEMETRY_MISSING,
         ev="backend/edr_plane/contracts/response.py::ResponseResult.verify",
         wave="Wave 6"),
    _cap("backend.control.outbreak", Plane.BACKEND, "control fabric",
         "Outbreak control",
         "Hash/certificate/application/IP/domain/URL block-allow, YARA, "
         "behavioural and exploit rules, device isolation, fleet "
         "remediation — each through policy -> scope -> approval -> "
         "deployment -> ack -> enforcement telemetry -> verification.",
         gap=GC.CONTROL_DRIVER_MISSING, driver=_A,
         note="No routes exist. Not started.", wave="Wave 10"),
    _cap("backend.control.application_control", Plane.BACKEND,
         "control fabric", "Application control",
         "Allow/block execution by hash, path or certificate.",
         gap=GC.CONTROL_DRIVER_MISSING, driver=_A, wave="Wave 6"),
    _cap("backend.control.network_block", Plane.BACKEND, "control fabric",
         "Network block / firewall (DFC)",
         "Endpoint-enforced IP/CIDR/domain blocking.",
         gap=GC.CONTROL_DRIVER_MISSING, driver=_A,
         note="Audit correction: the existing 'network blocking' surface is "
              "REPORT content, not enforcement.", wave="Wave 6"),
    _cap("backend.control.exploit_prevention", Plane.BACKEND,
         "control fabric", "Exploit prevention",
         "On-endpoint exploit mitigation.",
         gap=GC.CONTROL_DRIVER_MISSING, driver=_A, wave="Wave 6"),
    _cap("backend.control.isolation", Plane.BACKEND, "control fabric",
         "Endpoint isolation / release",
         "Network-contain an endpoint and release it, with verified state.",
         gap=GC.CONTROL_DRIVER_MISSING, driver=_A,
         note="Isolation state is genuinely UNKNOWN today, so the console "
              "offers neither Start nor Release — offering either would "
              "imply a state we do not have.", wave="Wave 6"),
]

SERVICE_CAPABILITIES: list[Capability] = [
    _cap("backend.service.file_trajectory", Plane.BACKEND, "investigation",
         "File trajectory (per-file)",
         "Entry point, created-by, known names/paths, first/last seen, "
         "observation count, affected endpoints.",
         state=FS.BACKEND_IMPLEMENTED, backend=_P, ui=_P, telemetry=_N,
         test=_P, contract=_P, gap=GC.TELEMETRY_MISSING,
         ev="backend/services/edr/file_trajectory.py · "
            "GET /api/edr/file-trajectory",
         note="Audit headline: BUILT, HONEST and STARVED. Reports "
              "content_digests_available=false rather than fake a hash "
              "match. BIND, do not rebuild."),
    _cap("backend.service.fleet_spread", Plane.BACKEND, "investigation",
         "Fleet file propagation / spread index",
         "Cross-endpoint propagation with patient zero and lateral spread.",
         state=FS.BACKEND_IMPLEMENTED, backend=_P, ui=_P, telemetry=_N,
         test=_P, contract=_P, gap=GC.TELEMETRY_MISSING,
         ev="GET /api/edr/fleet-spread-index · "
            "backend/detection_content/xdr_spread_watchlist.py",
         note="BIND, do not rebuild."),
    _cap("backend.service.device_trajectory", Plane.BACKEND, "investigation",
         "Device trajectory projection",
         "Time-ordered per-endpoint activity across system, process, file, "
         "network and registry lanes.",
         state=FS.REAL_ENDPOINT_VALIDATED, backend=_P, ui=_P, telemetry=_P,
         test=_P, e2e=_P, contract=_P, gap=GC.NONE,
         ev="GET /api/edr/device-trajectory · "
            "tests/edr/test_p1_10b_process_evidence_honesty.py · "
            "scripts/p0_b_sensor_proof.py",
         note="P0-D: renders REAL evidence from the enrolled Linux sensor "
              "on this host, and the platform-minted endpoint_id is now a "
              "valid pivot (resolved_via=endpoint_id). Gates `process` on "
              "real process evidence and emits process_state "
              "OBSERVED|UNKNOWN — an IP can no longer be rendered as a "
              "process lifeline. One real activity yields exactly one "
              "evidence row; a re-observation is linked, never re-counted."),
    _cap("backend.service.process_tree", Plane.BACKEND, "investigation",
         "Process tree / ancestry",
         "Root-first ancestry with honest ghost roots.",
         state=FS.BACKEND_IMPLEMENTED, backend=_P, ui=_P, telemetry=_P,
         test=_P, contract=_P, gap=GC.NONE,
         ev="GET /api/edr/process-tree · "
            "tests/edr/test_p0_b_linux_sensor.py::"
            "test_lineage_reaches_ces_so_a_process_tree_can_actually_link",
         note="REAL PID/PPID lineage now exists: the Linux sensor resolves "
              "the parent in /proc and refuses to attribute one when the "
              "pid may have been reused, and the child's parent_iid equals "
              "the parent's own process_iid so the tree links. NOT yet "
              "claimed: the /api/edr/process-tree ROUTE itself has not been "
              "re-proven against sensor evidence — it still projects "
              "ActivityInventory. CEF/LEEF remain parentless by "
              "specification."),
    _cap("backend.service.endpoint_inventory", Plane.BACKEND, "investigation",
         "Endpoint inventory",
         "The fleet list with identity confidence and health.",
         state=FS.GOLDEN_CORPUS_VALIDATED, backend=_P, ui=_P, telemetry=_N,
         test=_P, e2e=_P, contract=_P,
         ev="GET /api/edr/endpoints · backend/services/edr/device_identity.py",
         note="A device exists here only because an observation exists. An "
              "IP is never an endpoint."),
    _cap("backend.service.observation_narrative", Plane.BACKEND,
         "investigation", "Activity inspector narrative",
         "Prose activity detail for a single observation.",
         state=FS.BACKEND_IMPLEMENTED, backend=_P, telemetry=_N, test=_N,
         contract=_P, ev="GET /api/edr/observation-narrative"),
    _cap("backend.service.detections", Plane.BACKEND, "investigation",
         "Endpoint detections surface",
         "Detection events bound to endpoints.",
         state=FS.BACKEND_IMPLEMENTED, backend=_P, ui=_P, telemetry=_N,
         test=_N, contract=_P, ev="GET /api/edr/detections"),
    _cap("backend.service.file_repository", Plane.BACKEND, "investigation",
         "File repository + state machine",
         "Available / Requested / Processing / Failed / Rejected, with hash, "
         "metadata, provenance and analysis bindings.",
         gap=GC.TELEMETRY_MISSING,
         note="No routes. Requires File Fetch, which requires an agent.",
         wave="Wave 2"),
    _cap("backend.service.file_fetch", Plane.BACKEND, "investigation",
         "File fetch from endpoint",
         "Retrieve a file's bytes from the endpoint for analysis.",
         gap=GC.CONTROL_DRIVER_MISSING, driver=_A, wave="Wave 2"),
    _cap("backend.service.forensic_snapshot", Plane.BACKEND, "investigation",
         "Forensic snapshot",
         "Point-in-time endpoint inventory: processes, files, network, "
         "services, tasks, startup, users, PowerShell, USB, memory metadata.",
         gap=GC.TELEMETRY_MISSING, wave="Wave 7"),
    _cap("backend.service.live_query", Plane.BACKEND, "investigation",
         "Live query",
         "Ad-hoc real-time query against a live endpoint.",
         gap=GC.TELEMETRY_MISSING,
         note="Zero routes. The UI is an honest reserved page, not a mock.",
         wave="Wave 7"),
    _cap("backend.service.threat_intel", Plane.BACKEND, "investigation",
         "Threat intelligence enrichment",
         "Hash / IP / domain reputation enrichment.",
         state=FS.BACKEND_IMPLEMENTED, backend=_P, telemetry=_N, test=_N,
         contract=_P, ev="backend/routers/artifacts.py · settings.osint keys",
         note="VirusTotal, AbuseIPDB, URLScan, OTX and Hybrid Analysis are "
              "configured."),
    _cap("backend.service.malware_analysis", Plane.BACKEND, "investigation",
         "Malware analysis (static)",
         "Artifact router -> static analysis -> decoder -> embedded artifact "
         "extraction -> YARA -> intelligence -> verdict.",
         state=FS.OPERATIONAL, backend=_P, telemetry=_N, test=_P, e2e=_P,
         contract=_P,
         ev="backend/services/decoder/ · tests/decoder_harness/ (59 tests)",
         note="Operational for submitted artifacts. No endpoint artifact "
              "reaches it because File Fetch does not exist."),
    _cap("backend.service.sandbox", Plane.BACKEND, "investigation",
         "Dynamic sandbox",
         "Runtime detonation producing dynamic evidence.",
         gap=GC.TELEMETRY_MISSING,
         note="Owner-confirmed at P3: it would add a ninth evidence producer "
              "while eight existing consumers sit starved.", wave="Wave 8"),
    _cap("backend.service.retrospective_detection", Plane.BACKEND,
         "investigation", "Retrospective detection",
         "Re-run improved detection content over retained raw evidence.",
         state=FS.CONTRACT_DEFINED, contract=_P, backend=_N, test=_P,
         ev="backend/edr_plane/raw_events.py::replay_candidates",
         note="The audit found raw evidence IS retained, so this is "
              "self-contained and high value.", wave="Wave 9"),
    _cap("backend.service.audit_ledger", Plane.BACKEND, "governance",
         "Audit / change history",
         "Tamper-evident audit of access, change and action.",
         state=FS.OPERATIONAL, backend=_P, ui=_P, telemetry=_N, test=_P,
         e2e=_P, contract=_P,
         ev="21 audit routes · 7164 + 46856 + 55641 audit rows",
         note="Audit correction: this was understated in the prior matrix."),
    _cap("backend.service.rbac", Plane.BACKEND, "governance",
         "RBAC / authorization",
         "Permission enforcement with 11 starter roles and ACCESS_DENIED "
         "audit events.",
         state=FS.BACKEND_IMPLEMENTED, backend=_P, ui=_P, test=_P,
         contract=_P,
         telemetry=_NA, ev="/api/xdr/rbac/* · backend/deps.py",
         note="Enforced and unit-tested, but never proven end-to-end "
              "through the public ingress, so it is not declared "
              "OPERATIONAL. Bootstrap-allow applies while a tenant has zero "
              "users — which is why preview ingest needs no bearer token."),
    _cap("backend.service.tenant_isolation", Plane.BACKEND, "governance",
         "Multi-tenant isolation",
         "Cross-tenant access is refused before resource lookup.",
         state=FS.END_TO_END_VALIDATED, backend=_P, test=_P, e2e=_P,
         contract=_P, telemetry=_N,
         ev="tests/edr/test_cross_tenant.py (20 tests)"),
]


# ══ PLANE C · ANALYST / ADMINISTRATOR EXPERIENCE ══════════════════

_EXPERIENCE = [
    ("dashboard", "Dashboard", FS.BACKEND_IMPLEMENTED, _P, _P, GC.NONE,
     "apps/nivxray-xdr/src/xdr/pages/XdrDashboardPage.jsx", None),
    ("inbox", "Inbox", FS.BACKEND_IMPLEMENTED, _P, _P, GC.NONE,
     "XdrIncidentsPage.jsx", "Incident queue serves as the inbox today."),
    ("endpoint_overview", "Endpoint overview (Entity 360)",
     FS.GOLDEN_CORPUS_VALIDATED, _P, _P, GC.NONE,
     "XdrEntity360Page.jsx · test_reports/iteration_88.json", None),
    ("endpoint_details_drawer", "Endpoint details drawer",
     FS.GOLDEN_CORPUS_VALIDATED, _P, _P, GC.NONE,
     "EndpointDetailsDrawer.jsx · test_reports/iteration_88.json",
     "Every field states what is known; ◇ NO EVIDENCE and ⊘ CAPABILITY "
     "UNAVAILABLE with reasons. Zero fabricated values."),
    ("endpoint_actions_menu", "Endpoint actions menu",
     FS.GOLDEN_CORPUS_VALIDATED, _P, _P, GC.CONTROL_DRIVER_MISSING,
     "EndpointActionsMenu.jsx · test_reports/iteration_88.json",
     "Three states only: available / unavailable / no_evidence. 10 of 20 "
     "actions are disabled with the missing driver named. There is "
     "deliberately no state where a control looks live and does nothing."),
    ("events_ledger", "Events ledger", FS.BACKEND_IMPLEMENTED, _P, _P,
     GC.NONE, "XdrEvidenceExplorerPage.jsx", None),
    ("device_trajectory_ui", "Device trajectory canvas",
     FS.GOLDEN_CORPUS_VALIDATED, _P, _P, GC.NONE,
     "XdrDeviceTrajectoryPage.jsx · trajectoryModel.js (17 assertions)",
     "D3 swimlanes, lifelines, glyphs. Renders an explicit 'NO PROCESS "
     "EVIDENCE' band rather than inferring a lifeline."),
    ("macro_navigator", "30-day macro navigator", FS.UI_IMPLEMENTED, _N, _P,
     GC.NONE, "docs/uiux/NIVXFORGE_EDR_TARGET_UX_ARCHITECTURE.md",
     "Specified with event-density scaling and exact-day loading. Needs "
     "verification against the current build."),
    ("micro_scrubber", "24-hour micro scrubber", FS.UI_IMPLEMENTED, _N, _P,
     GC.NONE, "docs/uiux/NIVXFORGE_EDR_TARGET_UX_ARCHITECTURE.md", None),
    ("activity_inspector", "Activity inspector", FS.BACKEND_IMPLEMENTED, _P,
     _P, GC.NONE, "GET /api/edr/observation-narrative",
     "Activity detail is prose, not a field table."),
    ("ghost_roots", "Honest ghost roots", FS.CONTRACT_DEFINED, _N, _N,
     GC.TELEMETRY_MISSING,
     "backend/edr_plane/contracts/identity.py::LINEAGE_PRESENTATION",
     "Three lineage states contracted. The UI must render "
     "[ROOT / PARENT NOT OBSERVED] and never invent explorer.exe."),
    ("process_tree_ui", "Process tree UI", FS.BACKEND_IMPLEMENTED, _P, _P,
     GC.TELEMETRY_MISSING, "/edr/process-tree", None),
    ("file_intelligence", "File intelligence", FS.BACKEND_IMPLEMENTED, _N,
     _P, GC.TELEMETRY_MISSING, "/edr/files · EdrReservedPages.jsx",
     "Honest reserved surface — not a mock."),
    ("file_trajectory_ui", "File trajectory UI", FS.BACKEND_IMPLEMENTED, _P,
     _P, GC.TELEMETRY_MISSING, "XdrFleetFileTrajectoryPage.jsx", None),
    ("fleet_file_trajectory_ui", "Fleet file trajectory UI",
     FS.BACKEND_IMPLEMENTED, _P, _P, GC.TELEMETRY_MISSING,
     "XdrFleetFileTrajectoryPage.jsx · GET /api/edr/fleet-spread-index",
     None),
    ("sha256_pivot_menu", "SHA-256 universal pivot menu", FS.NOT_IMPLEMENTED,
     _N, _A, GC.NONE, "docs/uiux/NIVXFORGE_EDR_TARGET_UX_ARCHITECTURE.md:167",
     "Cisco baseline (14 pivots) plus the NivXRay extension (15) is "
     "specified. Not built as a context menu."),
    ("network_ui", "Network investigation UI", FS.NOT_IMPLEMENTED, _A, _P,
     GC.UI_ONLY, "/edr/network · EdrReservedPages.jsx",
     "Honest reserved page. No network investigation backend."),
    ("dns_ui", "DNS activity UI", FS.NOT_IMPLEMENTED, _A, _N,
     GC.TELEMETRY_MISSING,
     "docs/uiux/NIVXFORGE_EDR_TARGET_UX_ARCHITECTURE.md:66",
     "DESIGN-READY, API missing."),
    ("threat_hunting_ui", "Threat hunting UI", FS.NOT_IMPLEMENTED, _A, _P,
     GC.UI_ONLY, "/edr/hunting · EdrReservedPages.jsx", None),
    ("forensics_ui", "Forensics UI", FS.NOT_IMPLEMENTED, _A, _P, GC.UI_ONLY,
     "/edr/forensics · EdrReservedPages.jsx", None),
    ("live_query_ui", "Live query UI", FS.NOT_IMPLEMENTED, _A, _P,
     GC.UI_ONLY, "/edr/live-query · XdrReservedPage.jsx",
     "Audit finding: UI-only, zero routes. Honestly declared "
     "NOT_CONFIGURED on screen."),
    ("malware_analysis_ui", "Malware analysis UI", FS.BACKEND_IMPLEMENTED,
     _P, _P, GC.NONE, "XdrInvestigationWorkspacePage.jsx", None),
    ("threat_intel_ui", "Threat intelligence UI", FS.BACKEND_IMPLEMENTED,
     _P, _P, GC.NONE, "XdrKbPage.jsx", None),
    ("detections_ui", "Detections UI", FS.BACKEND_IMPLEMENTED, _P, _P,
     GC.NONE, "XdrDetectionsPage.jsx · /edr/detections", None),
    ("outbreak_control_ui", "Outbreak control UI", FS.NOT_IMPLEMENTED, _A,
     _A, GC.CONTROL_DRIVER_MISSING, None, "Not started."),
    ("computer_management_ui", "Computer management UI", FS.NOT_IMPLEMENTED,
     _A, _N, GC.CONTROL_DRIVER_MISSING, "XdrEndpointsPage.jsx",
     "The endpoint list exists but the management filters (Installed / Not "
     "Seen / AV Update / Connector Update / Fault / High Risk) and actions "
     "(Isolate / Scan / Diagnose / Move Group / Remote Uninstall) do not."),
    ("groups_policies_ui", "Groups & policies UI", FS.NOT_IMPLEMENTED, _A,
     _A, GC.CONTROL_DRIVER_MISSING, None,
     "No policy plane is bound to any endpoint."),
    ("connector_diagnostics_ui", "Connector diagnostics UI",
     FS.NOT_IMPLEMENTED, _N, _N, GC.TELEMETRY_MISSING,
     "backend/routers/xdr_collectors.py",
     "Audit correction: the existing 'remote diagnostics' is preview-build "
     "diagnostics, unrelated to endpoints."),
    ("endpoint_health_ui", "Endpoint health UI", FS.GOLDEN_CORPUS_VALIDATED,
     _P, _P, GC.NONE, "test_reports/iteration_88.json",
     "Both dimensions rendered separately with reasons, plus the "
     "epistemic-honesty note."),
    ("response_ui", "Response UI", FS.NOT_IMPLEMENTED, _N, _P,
     GC.CONTROL_DRIVER_MISSING, "/edr/response · EdrReservedPages.jsx",
     None),
    ("enrollment_ui", "Endpoint enrolment UI", FS.NOT_IMPLEMENTED, _A, _A,
     GC.NONE, None,
     "Owner-locked minimal scope: generate one-time token, show once, TTL, "
     "single-use status, enrolled endpoints, credential status, revoke."),
    ("administration_ui", "Administration UI", FS.BACKEND_IMPLEMENTED, _P,
     _P, GC.NONE, "XdrAdminPage.jsx", None),
    ("filter_taxonomy", "43-item filter taxonomy", FS.CONTRACT_DEFINED, _A,
     _N, GC.OWNER_INPUT_PENDING,
     "backend/edr_plane/capability/taxonomy.py",
     "The five categories are known (Activity, System, Disposition, Flags, "
     "File Types). The verbatim 43 items are NOT in this repository and "
     "were NOT reconstructed from memory. Owner input pending."),
]

EXPERIENCE_CAPABILITIES: list[Capability] = [
    _cap(f"experience.{k}", Plane.EXPERIENCE, "analyst console", n,
         f"{n} surface of the NivXForge EDR console.",
         state=st, backend=be, ui=ui, gap=gap, contract=_P if be != _A else _A,
         telemetry=_N if be == _P else _A,
         test=_P if ev and "iteration" in (ev or "") else _A,
         e2e=_P if ev and "iteration" in (ev or "") else _A,
         ev=ev, note=note)
    for k, n, st, be, ui, gap, ev, note in _EXPERIENCE
]


INVENTORY: list[Capability] = (
    AGENT_CAPABILITIES + PIPELINE_CAPABILITIES + REASONING_CAPABILITIES
    + DETECTION_CAPABILITIES + CONTROL_CAPABILITIES + SERVICE_CAPABILITIES
    + EXPERIENCE_CAPABILITIES
)

#: P0-B · the Linux sensor is REAL and registered. `fields_supported`
#: is the sensor's own attested list, so anything absent from it resolves
#: NOT_SUPPORTED rather than NOT_OBSERVED — the difference between "this
#: sensor cannot tell us" and "it told us nothing happened".
SENSOR_REGISTRY: list[SensorCapability] = [
    SensorCapability(
        sensor_id="nivxforge-linux", platform="LINUX",
        sensor_version="0.1.0",
        collects=["PROCESS", "FILE", "NETWORK"],
        fields_supported=[
            "process.pid", "process.ppid", "process.image",
            "process.image_path", "process.sha256", "process.command_line",
            "process.user", "process.start_time",
            "file.path", "file.filename", "file.size", "file.sha256",
            "file.operation",
            "network.protocol", "network.local_ip", "network.local_port",
            "network.remote_ip", "network.remote_port", "network.direction",
        ],
        response_actions=[],   # no driver: every action is ⊘ NOT REGISTERED
        attested_at="2026-06-01",
        attested_by="tests/edr/test_p0_b_linux_sensor.py — collection "
                    "verified against live /proc, not a fixture"),
]


def summary() -> dict:
    from collections import Counter
    eff = Counter(c.effective_state for c in INVENTORY)
    gaps = Counter(c.gap_class for c in INVENTORY)
    planes = Counter(c.plane for c in INVENTORY)
    return {
        "total": len(INVENTORY),
        "by_effective_state": dict(eff),
        "by_gap_class": dict(gaps),
        "by_plane": dict(planes),
        "operational": sum(1 for c in INVENTORY if c.is_operational),
        "downgraded_claims": sum(1 for c in INVENTORY
                                 if not c.claim_is_honest),
        "sensors_registered": len(SENSOR_REGISTRY),
        "grading_rule": (
            "No capability is considered implemented merely because a "
            "route, UI component, stub, simulator, or contract exists."),
    }


def by_id(capability_id: str) -> Capability | None:
    return next((c for c in INVENTORY
                 if c.capability_id == capability_id), None)
