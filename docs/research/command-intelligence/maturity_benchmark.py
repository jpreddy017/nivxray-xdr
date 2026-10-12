"""Same-corpus before/after evaluator. No payload execution or external access."""
import json,time,resource,sys
from pathlib import Path
from services.decoder.automatic import analyze,replay_recipe
sys.path.insert(0,str(Path(__file__).resolve().parents[3]/'backend/tests/fixtures/command_maturity'))
from corpus import cases

def run():
    results=[]
    for c in cases():
        start=time.perf_counter();r=analyze(c['input']);ms=(time.perf_counter()-start)*1000
        canon=r['canonical_decoded_artifact']; expected=c['expected'];policy=c['policy']
        correct=(r['final_recoverable']['value']==expected and canon['promoted']) if policy=='full' else (not canon['promoted'] and any(x['payload']['value']==expected for x in r['candidates'])) if policy=='partial' else (not canon['promoted'])
        behavior=c['behavior']; behavior_ok=True if behavior is None else all(b.get('kind')=='output_display' for b in r['behaviors']) if behavior=='output_only' else any(b.get('kind')==behavior for b in r['behaviors'])
        recipes=all(replay_recipe(c['input'],x['recipe'])==x['payload'] for x in r['candidates'])
        results.append(dict(name=c['name'],policy=policy,correct=correct,behavior_correct=behavior_ok,recipe_correct=recipes,status=r['decode_status'],output=r['final_recoverable'],canonical=canon['promoted'],latency_ms=round(ms,3),nodes=r['search']['visited'],generated_bytes=r['search']['output_bytes']))
    return dict(cases=len(results),correct=sum(x['correct'] for x in results),behavior_cases=sum(c['behavior'] is not None for c in cases()),behavior_correct=sum(x['behavior_correct'] for x,c in zip(results,cases()) if c['behavior'] is not None),recipe_correct=sum(x['recipe_correct'] for x in results),peak_process_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,results=results)
if __name__=='__main__': print(json.dumps(run(),indent=2))
