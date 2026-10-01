# WORKSPACE Buttons × 4 Payloads — Live Regression Matrix

| Sample | SMART | MAGIC | AI DECODE | ANALYZE | PREDICT TREE |
|---|---|---|---|---|---|
| `S1_base32_blob` | HTTP 200 · 975ms · chain 2 | HTTP 200 · 4356ms | HTTP 200 · 3ms · engine magic · conf 50 · **cache** | HTTP 200 · 6987ms · verdict None · IOCs 1 · MITRE 1  · ⚠AI | HTTP 200 · 38546ms · src None · root None |
| `S2_ps_frombase64_shellcode` | HTTP 200 · 5701ms · chain 3 | HTTP 200 · 1581ms | HTTP 200 · 4ms · engine magic · conf 54 · **cache** | HTTP 200 · 55204ms · verdict None · IOCs 2 · MITRE 4  · ⚠AI | HTTP 200 · 40095ms · src None · root None |
| `S3_cmd_caret_ps_xor` | HTTP 200 · 5097ms · chain 2 | HTTP 200 · 2944ms | HTTP 200 · 4ms · engine magic · conf 70 · **cache** | HTTP 200 · 55382ms · verdict None · IOCs 0 · MITRE 3  · ⚠AI | HTTP 200 · 40411ms · src None · root None |
| `S4_iex_binary_download` | HTTP 200 · 4471ms · chain 1 | HTTP 200 · 17ms | HTTP 200 · 4ms · engine plaintext-guard · conf 100 | HTTP 200 · 55293ms · verdict None · IOCs 0 · MITRE 1  · ⚠AI | HTTP 200 · 28658ms · src None · root None |