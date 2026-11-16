// @vitest-environment jsdom
import React from 'react';
import {render,screen,fireEvent,waitFor,cleanup} from '@testing-library/react';
import {MemoryRouter} from 'react-router-dom';
import {vi,test,expect,afterEach,beforeEach} from 'vitest';
import {ForensicsContent} from './ForensicsWorkspace';
import {coverage,scoped,validateJob,snapshotError} from './snapshot-contract.mjs';
const mocks=vi.hoisted(()=>({get:vi.fn(),post:vi.fn(),tenant:'tenant-a'}));
vi.mock('@/lib/api',()=>({default:{get:mocks.get,post:mocks.post}}));
vi.mock('@/lib/tenant',()=>({activeTenant:()=>mocks.tenant,TENANT_BOUND_EVENT:'tenant-change'}));
vi.mock('@/nivxforge/NivXForgeConsole',()=>({default:({children})=><>{children}</>}));
vi.mock('./CommandAnalyzerPreview',()=>({default:()=> <h2>Analyzer fixture</h2>}));
const job={tenant_id:'tenant-a',job_id:'job-a',endpoint_id:'ep-a',status:'COMPLETED_WITH_ROWS',row_count:1,rows:[{pid:20,name:'example',path:'/usr/bin/example'}]};
beforeEach(()=>{mocks.tenant='tenant-a';mocks.get.mockReset();mocks.post.mockReset();mocks.get.mockImplementation(async(url)=>({data:url.includes('onboarding')?{tenant_id:'tenant-a',computers:[{endpoint_id:'ep-a',hostname:'Test endpoint',status:'CONNECTED'}]}:url.endsWith('/job-a')?job:{tenant_id:'tenant-a',jobs:[]}}));});
afterEach(cleanup);
test('extended profiles stay disabled until endpoint capability is advertised',async()=>{
 mocks.get.mockImplementation(async()=>({data:{tenant_id:'tenant-a',computers:[],jobs:[],categories:[{id:'os_version',name:'Operating system'}],windows_ready:false}}));
 mount('/edr/forensics?section=snapshot&device=ep-a');
 await screen.findByText(/No compatible collector has been advertised/);
 expect(screen.getByRole('option',{name:/all 41 categories/}).disabled).toBe(true);
});
test('full profile posts its explicit selection and shows per-category failures',async()=>{
 const full={...job,status:'COMPLETED_PARTIAL',rows:[],categories:[{category_id:'os_version',name:'Operating system',state:'COLLECTED',rows:[{Caption:'Test Windows'}],row_count:1},{category_id:'services',name:'Services',state:'UNAVAILABLE',rows:[],row_count:0,detail:'Provider access denied'}]};
 mocks.get.mockImplementation(async url=>({data:url.endsWith('/job-a')?full:{tenant_id:'tenant-a',computers:[{endpoint_id:'ep-a',hostname:'Test endpoint'}],jobs:[],categories:[{id:'os_version',name:'Operating system'}],windows_ready:true}}));
 mocks.post.mockResolvedValue({data:full});mount('/edr/forensics?section=snapshot&device=ep-a');
 await waitFor(()=>expect(screen.getByRole('option',{name:/all 41 categories/}).disabled).toBe(false));
 fireEvent.change(screen.getByLabelText('Collection profile'),{target:{value:'windows_full'}});fireEvent.change(screen.getByLabelText('Reason'),{target:{value:'case full'}});fireEvent.click(screen.getByRole('button',{name:'Take Forensic Snapshot'}));
 await screen.findByText('Test Windows');expect(mocks.post).toHaveBeenCalledWith('/edr/forensics/snapshots',{endpoint_id:'ep-a',reason:'case full',profile:'windows_full'});
 fireEvent.click(screen.getByRole('button',{name:'Inspect Running Services Monitoring'}));await screen.findByText(/Provider access denied/);expect(screen.queryByText('Test Windows')).toBeNull();
});
const mount=url=>render(<MemoryRouter initialEntries={[url]}><ForensicsContent/></MemoryRouter>);
test('folder opens two distinct views and supports back to parent',async()=>{mount('/edr/forensics');expect(screen.getByRole('navigation',{name:'Forensics breadcrumb'})).toBeTruthy();fireEvent.click(screen.getByRole('link',{name:/Command-line Analyzer Decode/}));expect(screen.getByText('Analyzer fixture')).toBeTruthy();expect(screen.queryByRole('region',{name:'Forensic Snapshot'})).toBeNull();fireEvent.click(screen.getByRole('link',{name:'Forensics',exact:true}));fireEvent.click(screen.getByRole('link',{name:/Forensic Snapshot Request/}));await screen.findByText('No snapshot requests were returned for this selection.');expect(screen.queryByText('Analyzer fixture')).toBeNull();});
test('request stays bound to selected endpoint and opens evidence',async()=>{mocks.post.mockResolvedValue({data:job});mount('/edr/forensics?section=snapshot');await screen.findByRole('option',{name:/Test endpoint/});fireEvent.change(screen.getByLabelText('Snapshot computer'),{target:{value:'ep-a'}});fireEvent.change(screen.getByLabelText('Reason'),{target:{value:'Investigate case 123'}});fireEvent.click(screen.getByRole('button',{name:'Take Forensic Snapshot'}));await screen.findByText('/usr/bin/example');expect(mocks.post).toHaveBeenCalledWith('/edr/forensics/snapshots',{endpoint_id:'ep-a',reason:'Investigate case 123'});expect(screen.getByRole('button',{name:'Export evidence JSON'})).toBeTruthy();});
test('failed history is not represented as an empty history',async()=>{mocks.get.mockRejectedValue({response:{data:{detail:{reason:'Service unavailable'}}}});mount('/edr/forensics?section=snapshot');await screen.findByText('History unavailable: Service unavailable');expect(screen.queryByText('No snapshot requests were returned for this selection.')).toBeNull();});
test('cross-customer evidence is rejected',async()=>{mocks.get.mockImplementation(async url=>({data:url.endsWith('/job-a')?{...job,tenant_id:'tenant-b'}:{tenant_id:'tenant-a',jobs:[],computers:[]}}));mount('/edr/forensics?section=snapshot&job=job-a');await screen.findByRole('button',{name:'Retry evidence'});expect(screen.queryByText('/usr/bin/example')).toBeNull();});
test('legacy device/job links open snapshot child directly',async()=>{mount('/edr/forensics?device=ep-a&job=job-a');await screen.findByText('/usr/bin/example');expect(screen.queryByText('Analyzer fixture')).toBeNull();});
test('pending and failed captures never claim collected processes',()=>{for(const status of ['QUEUED','RUNNING','FAILED','TIMED_OUT','CAPABILITY_UNAVAILABLE'])expect(coverage({status})[0].state).toBe('NOT_COLLECTED');expect(coverage({...job,rows_truncated:true})[0].state).toBe('PARTIAL');});
test('contract rejects tenant and job mismatches and formats structured errors',()=>{expect(()=>scoped({tenant_id:'b'},'a')).toThrow();expect(()=>validateJob(job,'tenant-a','different')).toThrow();expect(snapshotError({response:{data:{detail:[{msg:'Invalid endpoint'}]}}})).toBe('Invalid endpoint');});

test('legacy snapshots expose all 41 named categories without claiming missing evidence',async()=>{
 mount('/edr/forensics?device=ep-a&job=job-a');await screen.findByText('/usr/bin/example');
 for(const name of ['Powershell History','Installed Programs On Windows Host','Users - Logged-in','UserAssist Monitoring','Windows ShellBags Monitoring','Windows ShimCache Monitoring'])expect(screen.getByRole('button',{name:`Inspect ${name}`})).toBeTruthy();
 fireEvent.click(screen.getByRole('button',{name:'Inspect Powershell History'}));expect(screen.getByText(/This snapshot did not collect this category/)).toBeTruthy();expect(screen.queryByText('/usr/bin/example')).toBeNull();
 fireEvent.click(screen.getByRole('button',{name:'Close snapshot'}));expect(screen.queryByRole('dialog')).toBeNull();fireEvent.click(screen.getByRole('button',{name:'View Snapshot'}));expect(screen.getByRole('dialog')).toBeTruthy();
});
