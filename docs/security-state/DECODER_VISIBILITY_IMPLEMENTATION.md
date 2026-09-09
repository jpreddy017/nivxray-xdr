# NivXRay XDR — Decoder Visibility Implementation & Bug Fixes

## 1. Overview & Architecture Principles

The goal of this implementation is to eliminate the visibility and data-retention defect in NivXRay XDR without creating competing decoder engines. The architecture strictly adheres to three principles:

1. **No Decoder Duplication**:
   - **Deterministic Decoder Orchestrator (DDO)** (`backend/services/decoder/orchestrator.py`) remains the authoritative execution orchestrator.
   - **Universal Decoder** (`backend/services/decoder/engine.py`), **Command Reconstruction Engine (CRE)**, and all 46+ codecs in `backend/decoders/` are preserved and directly reused.
   - Legacy and bridge interfaces delegate to DDO; no secondary or redundant engines were introduced.
2. **Every Stage is Evidence**:
   - Every transformation step must retain complete forensic context:
     - `stage_id`: Unique deterministic identifier (`layer_1`, `layer_2`, etc.)
     - `sequence`: 1-based sequential index
     - `decoder`: Canonical codec name/operation ID
     - `input_hash`: SHA-256 digest of pre-transformation buffer
     - `input_length`: Byte count before decoding
     - `input_preview`: First 200–400 characters of input
     - `output_hash`: SHA-256 digest of transformed buffer
     - `output_length`: Byte count after decoding
     - `output_preview`: First 200–400 characters of output
     - `output_payload`: Size-bounded payload (up to 64KB) for forensic reconstruction
     - `status`: `"success"`, `"failed"`, or `"fallback"`
     - `why_selected`: Deterministic explanation for selecting this decoder
     - `confidence`: Confidence score (0.0 to 1.0 or 0 to 100)
     - `duration_ms`: Execution latency in milliseconds
     - `stop_reason`: Clear reason explaining why the pipeline halted or did not apply further transformations
3. **Explicit Semantic Bridge**:
   - Decoding does not terminate at displaying text. Decoded output directly feeds into the Semantic Engine (`services.die.api.analyze`), IOC extraction, MITRE ATT&CK mapping, and LOLBAS detection, providing verified evidence to the Investigation Knowledge Graph (IKG) and Security State.

```text
Raw Command
    ↓
Canonical Command
    ↓
Deterministic Decoder Orchestrator (DDO)
    ↓
Decode Stage 1 (Base64) ──→ Stage Evidence (hashes, preview, why)
    ↓
Decode Stage 2 (GZIP)   ──→ Stage Evidence (hashes, preview, why)
    ↓
Decode Stage 3 (XOR)    ──→ Stage Evidence (hashes, preview, why)
    ↓
Final Decoded Payload (Plaintext / Shellcode)
    ↓
Semantic Engine (Command Language, LOLBAS, ATT&CK, Intent)
    ↓
Verdict Engine (Malicious / Suspicious / Benign / Undecoded)
    ↓
IKG / Security State (ABUSED_CAPABILITY / CONFIRMED_ATTACK)
```

---

## 2. Root Cause Analysis: The 4-Point Payload Loss Bug Chain

Prior to this fix, analysts reported that intermediate layers were invisible or appeared empty in the UI. Investigation revealed a cascading 4-point bug chain:

### Point 1: Intentional Payload Erasure in `decoder_bridge/__init__.py`
In `backend/services/decoder_bridge/__init__.py`, intermediate layers explicitly set `payload_text = ""`:
```python
# PREVIOUS DEFECTIVE CODE:
payload_text = (
    lyr.get("output_text")
    if (lyr is raw_layers[-1] and isinstance(lyr.get("output_text"), str))
    else ""  # <--- CRITICAL BUG: all intermediate payloads were wiped!
)
```
**Fix**: Passed the real `output_text` through every layer, bounded to 64KB for safety:
```python
# RESOLVED CODE:
raw_out = lyr.get("output_text") or lyr.get("text") or lyr.get("preview") or ""
payload_text = raw_out[:65536] if isinstance(raw_out, str) else str(raw_out)[:65536]
```

### Point 2: Missing Stage Payloads in `recursive_decoder.py`
In `backend/services/die/preprocessor/recursive_decoder.py`, `peel_recursively()` tracked stage names and lengths in `layers_meta`, but never recorded `output_text`, `input_hash`, or `output_hash`.
**Fix**: `peel_recursively()` now computes SHA-256 hashes of `input_buf` and `output_buf`, retains `output_text` (up to 64KB), maps stage names to human-readable `why_selected` rationales, and stamps a deterministic `stop_reason` onto every layer.

### Point 3: Attribute Misalignment in `rc22_adapter.py`
In `backend/rc22_adapter.py` (lines 280–295), the adapter converted `TraceStep` objects from `engine.Orchestrator` into stage dictionaries by querying:
```python
# PREVIOUS DEFECTIVE CODE:
"output_preview": st.output[:400] if hasattr(st, "output") else "",  # FAILED: TraceStep has no .output
"output_length": len(st.output) if hasattr(st, "output") else 0,      # FAILED: TraceStep has .out_len
"why": getattr(st, "notes", None) or "",                             # FAILED: TraceStep has .why
```
Because `TraceStep` defines `preview`, `out_len`, and `why`, all three checks failed silently, producing empty previews, zero lengths, and blank reasons.
**Fix**: Updated `rc22_adapter.py` to read `st.preview`, `st.out_len`, and `st.why`:
```python
# RESOLVED CODE:
"output_preview": getattr(st, "preview", "") or "",
"output_length": getattr(st, "out_len", 0),
"why": getattr(st, "why", "") or "",
```

### Point 4: Discordant Property Names Across Consumers
Different layers used conflicting property names:
- Operation: `op` vs `decoder` vs `stage`
- Reason: `reason` vs `why` vs `why_selected`
- Preview: `preview` vs `output_preview` vs `output_payload`
- Lengths: `in_len`/`out_len` vs `input_length`/`output_length`
- Latency: `exec_ms` vs `duration_ms`

**Fix**: Enriched `CanonicalDecodedLayer.to_dict()`, `DecodedLayer.to_dict()`, `TraceStep`, and `/decode/smart` with universal bidirectional aliases. Any UI or backend consumer can query either variant (`t.op` or `t.decoder`, `t.reason` or `t.why`) and receive identical values.

---

## 3. Implementation Details by Component

### A. Backend Preprocessor: `recursive_decoder.py`
- Added SHA-256 hashing before and after each peel.
- Added `why_selected` dictionary mapping stage operations (e.g. `base64_decode` $\to$ "Valid Base64 alphabet and length detected").
- Enforced 64KB payload bounds on `output_text`.
- Stamped `stop_reason` on every layer (`terminal_plaintext_reached`, `no_further_transformation`, `depth_budget_exhausted`).

### B. Decoder Bridge: `decoder_bridge/__init__.py`
- Restored `payload_text` propagation to all intermediate layers.
- Enriched `CanonicalDecodedLayer.to_dict()` with universal aliases.
- Updated `project_iocs()` to scan every intermediate layer, attributing extracted URLs/IPs to the specific layer that exposed them.

### C. Canonicalizer: `services/canonicalizer/__init__.py`
- Added `decoded_intelligence` field to `CanonicalCommand` dataclass.
- In `canonicalize()`, assembled the authoritative decoded intelligence bundle:
  - `raw_command`
  - `effective_payload`
  - `stages` (full forensic sequence)
  - `stop_reason`
  - `iocs`
  - `semantic_understanding` (via DIE API: command language, LOLBAS, ATT&CK techniques, intent)
  - `provenance` (engine, stage count, original and final lengths)

### D. Ops Router: `routers/ops.py` (`/decode/smart`)
- Hoisted `stop_reason` and `stopped_reason` to top-level response.
- Normalized every stage in `result["trace"]` with sequence index, hashes, previews, lengths, and reasons.
- Attached top-level `decoded_intelligence` matching the canonicalizer contract.

### E. Frontend UI: `DecodingTracePanel.jsx` & `AnalystWorkspacePage.jsx`
- Added `stopReason` prop to `DecodingTracePanel.jsx` and rendered a prominent `STOP REASON: ...` banner.
- Updated chip headers and layer rows to use safe property fallbacks (`t.op || t.decoder`, `t.reason || t.why || t.why_selected`, `t.output_preview || t.preview`).
- Added expandable forensic details displaying `input_hash`, `output_hash`, and `why_selected` rationales.
- Updated `AnalystWorkspacePage.jsx` Decode Timeline with corresponding fallbacks and stop reason display.

---

## 4. Deterministic Stop Reasons

The decoder engine strictly prohibits vague or silent halts. Every decode sequence terminates with one of the following deterministic reasons:

1. `terminal_plaintext_reached`: The decoded output satisfies english density, printable character ratios, and contains recognizable script tokens (PowerShell/CMD/Bash/Python).
2. `no_further_transformation`: The payload does not match any recognized encoding signature, container header, or obfuscation pattern.
3. `already_plaintext`: The input was already clear plaintext; no deobfuscation was necessary.
4. `corrupted_container_trailer`: An archive container (GZIP/ZLIB/BZIP2) was detected but the stream trailer or CRC checksum was invalid.
5. `depth_budget_exhausted`: Bounded recursion limit (default 20 layers) reached, preventing infinite recursion on self-referential inputs.
6. `crypto_key_required`: High-entropy block-aligned ciphertext was detected (AES/RC4), but no inline decryption key was found in the artifact.
