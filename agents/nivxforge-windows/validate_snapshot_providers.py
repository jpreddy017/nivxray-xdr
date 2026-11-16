"""Windows CI smoke gate. Logs metadata only, never collected artifacts."""
import json,os,sys
import windows_snapshot as s

if os.name!='nt':
 raise SystemExit('Native collector validation requires Windows')
result=s.collect(include_sensitive=True)
summary=[{'id':c['category_id'],'state':c['state'],'rows':c['row_count'],'error_type':c.get('error_type')} for c in result['categories']]
print(json.dumps({'collector_version':s.VERSION,'categories':summary}))
assert len(summary)==41
by_id={c['id']:c for c in summary}
for key in ('os_version','services','installed_programs','module_processes','hosts','root_certificates'):
 assert by_id[key]['state'] in ('COLLECTED','PARTIAL'),f'{key}: core Windows provider did not collect'
assert not any(c.get('error_type') in ('ParseException','CommandNotFoundException') for c in summary),'Missing command or parser failure'
print('Windows forensic provider smoke: PASS; per-category availability is reported above.')
