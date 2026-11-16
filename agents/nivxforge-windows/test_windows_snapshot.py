import json, sqlite3, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
import windows_snapshot as s
from windows_snapshot_worker import Worker, ACTION

class SnapshotTests(unittest.TestCase):
 def test_catalog_covers_all_41_categories(self):
  self.assertEqual(len(s.manifest()),41)
  self.assertEqual(len({x['id'] for x in s.manifest()}),41)
 def test_unknown_and_duplicate_selection_rejected(self):
  for keys in [[],['unknown'],['os_version','os_version']]:
   with self.assertRaises(ValueError):s.collect(keys)
 def test_sensitive_profile_never_runs_without_selection(self):
  seen=[]
  result=s.collect(['powershell_history','os_version'],runner=lambda k,timeout:(seen.append(k) or {'state':'COLLECTED','rows':[]}))
  self.assertEqual(seen,['os_version']);self.assertEqual(result['categories'][0]['state'],'NOT_SELECTED')
 def test_full_profile_dispatches_all_static_categories(self):
  seen=[]
  result=s.collect(include_sensitive=True,runner=lambda k,timeout:(seen.append(k) or {'state':'COLLECTED','rows':[{'category':k}]}))
  self.assertEqual(seen,list(s.CATALOG));self.assertEqual(len(result['categories']),41)
 def test_provider_failure_does_not_hide_other_categories(self):
  def runner(k,timeout):
   if k=='services':raise PermissionError()
   return {'state':'COLLECTED','rows':[{'x':1}]}
  result=s.collect(['services','os_version'],runner=runner)
  self.assertEqual([x['state'] for x in result['categories']],['FAILED','COLLECTED'])
 def test_output_budget_drops_oversized_category(self):
  result=s.collect(['os_version'],runner=lambda k,timeout:{'state':'COLLECTED','rows':[{'x':'x'*(s.MAX_TOTAL_BYTES+1)}]})
  self.assertEqual(result['categories'][0]['state'],'OUTPUT_LIMIT');self.assertEqual(result['categories'][0]['rows'],[])
 def test_cancel_does_not_run_queries(self):
  result=s.collect(['os_version'],cancelled=lambda:True,runner=lambda *a,**k:self.fail('query ran'))
  self.assertEqual(result['categories'][0]['state'],'BUDGET_EXHAUSTED')
 def test_checksum_matches_exact_canonical_evidence(self):
  result=s.collect(['os_version'],runner=lambda k,timeout:{'state':'COLLECTED','rows':[]});digest=result.pop('sha256')
  self.assertEqual(digest,s.hashlib.sha256(json.dumps(result,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest())
 def test_worker_replays_persisted_result_without_recollection(self):
  with tempfile.TemporaryDirectory() as folder:
   worker=Worker('https://example.invalid',{'endpoint_id':'ep_test','tenant_id':'test','agent_credential':'test'},folder)
   db=sqlite3.connect(':memory:');db.execute('create table jobs(id text primary key,result text,reported integer)')
   command={'command_id':'cmd_'+'a'*20,'action':ACTION,'target':{'categories':['os_version']}}
   with patch('windows_snapshot_worker.collector.collect',return_value={'categories':[{'state':'COLLECTED','rows':[]}]}) as collect:
    first=worker.process(db,command);second=worker.process(db,command)
    self.assertEqual(first,second);self.assertEqual(collect.call_count,1)
 def test_interrupted_job_not_silently_recaptured(self):
  worker=Worker('https://example.invalid',{'endpoint_id':'ep_test','tenant_id':'test','agent_credential':'test'},'.')
  db=sqlite3.connect(':memory:');db.execute('create table jobs(id text primary key,result text,reported integer)');cid='cmd_'+'b'*20;db.execute('insert into jobs values (?,NULL,0)',(cid,))
  with patch('windows_snapshot_worker.collector.collect') as collect:
   result=worker.process(db,{'command_id':cid,'action':ACTION});self.assertEqual(result['outcome'],'FAILED');collect.assert_not_called()
 def test_unknown_action_does_not_execute(self):
  worker=Worker('https://example.invalid',{'endpoint_id':'ep_test','tenant_id':'test','agent_credential':'test'},'.')
  db=sqlite3.connect(':memory:');db.execute('create table jobs(id text primary key,result text,reported integer)')
  with patch('windows_snapshot_worker.collector.collect') as collect:
   self.assertEqual(worker.process(db,{'command_id':'cmd_'+'c'*20,'action':'RUN_SCRIPT'})['outcome'],'CAPABILITY_UNAVAILABLE');collect.assert_not_called()

if __name__=='__main__':unittest.main()
