"""Re-run recorded synthetic reference cases against NivXRay (no external runtime)."""
import json
from pathlib import Path
from services.decoder.automatic import analyze
ROOT = Path(__file__).parent
for case in json.loads((ROOT/'cyberchef-11.5.0-restricted-results.json').read_text())['results']:
    result = analyze(case['input'])
    print(json.dumps({'case':case['name'],'reference_candidates':case['candidates'],'nivx_status':result['decode_status'],'nivx_output':result['final_recoverable']}))
for case in json.loads((ROOT/'minusone-0.4.1-results.json').read_text()):
    result = analyze(case['input'])
    print(json.dumps({'input':case['input'],'minusone':case['output'],'nivx_status':result['decode_status'],'nivx_output':result['final_recoverable']}))
