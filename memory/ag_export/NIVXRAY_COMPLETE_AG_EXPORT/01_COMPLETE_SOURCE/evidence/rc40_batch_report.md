# NivXRay RC4.0 · Batch Regression Evidence

- **API**: `http://localhost:8001`
- **Total cases**: 475
- **Passed**: 465 (97.9%)
- **Duration**: 390s
- **Latency**: p50=192ms · p95=6301ms

## By category

| Category | Pass | Fail | Rate |
| --- | --- | --- | --- |
| `batch-envvar` | 7 | 0 | 100% |
| `benign` | 5 | 0 | 100% |
| `cmd-substr` | 3 | 0 | 100% |
| `hex-pe` | 0 | 2 | 0% |
| `js-custom-b64-xor` | 1 | 0 | 100% |
| `js-html-smuggling` | 28 | 0 | 100% |
| `lolbas-wrapper` | 10 | 0 | 100% |
| `nested-b64-gzip` | 2 | 1 | 66% |
| `ps-encoded` | 70 | 0 | 100% |
| `ps-hex-csv` | 70 | 7 | 90% |
| `ps-hex-split-gzip` | 3 | 0 | 100% |
| `ps-iex-hidden` | 21 | 0 | 100% |
| `ps-regex-swap` | 49 | 0 | 100% |
| `ps-reverse` | 56 | 0 | 100% |
| `ps-xor-inline` | 140 | 0 | 100% |

## Failure samples

- `[ps-hex-csv]` **ps-hex-csv-7** — missing_all:['mppreference', 'add-mppreference'] · chain=['powershell-hex-csv-inline', 'base64-decode', 'family-emotet']
- `[ps-hex-csv]` **ps-hex-csv-7-mut0** — missing_all:['mppreference', 'add-mppreference'] · chain=['powershell-hex-csv-inline', 'base64-decode', 'family-emotet']
- `[ps-hex-csv]` **ps-hex-csv-7-mut1** — missing_all:['mppreference', 'add-mppreference'] · chain=['powershell-hex-csv-inline', 'base64-decode', 'family-emotet']
- `[ps-hex-csv]` **ps-hex-csv-7-mut2** — missing_all:['mppreference', 'add-mppreference'] · chain=['powershell-hex-csv-inline', 'base64-decode', 'family-emotet']
- `[ps-hex-csv]` **ps-hex-csv-7-mut3** — missing_all:['mppreference', 'add-mppreference'] · chain=['powershell-hex-csv-inline', 'base64-decode', 'family-emotet']
- `[ps-hex-csv]` **ps-hex-csv-7-mut4** — missing_all:['mppreference', 'add-mppreference'] · chain=['powershell-hex-csv-inline', 'base64-decode', 'family-emotet']
- `[ps-hex-csv]` **ps-hex-csv-7-mut5** — missing_all:['mppreference', 'add-mppreference'] · chain=['powershell-hex-csv-inline', 'base64-decode', 'family-emotet']
- `[nested-b64-gzip]` **nested-b64-gzip-0** — missing_all:['downloadstring'] · chain=['extract-payload', 'base64-decode', 'gzip-decompress', 'extract-payload', 'crypto-detect', 'ioc-extract', 'family-emotet']
- `[hex-pe]` **hex-pe-0** — missing_all:['MZ'] · chain=['ps-reconstruct']
- `[hex-pe]` **hex-pe-1** — missing_all:['MZ'] · chain=['certutil-annotate', 'extract-payload', 'hex-decode', 'utf16le-decode', 'utf16le-decode', 'utf16le-decode', 'xor-brute', 'extract-payload']