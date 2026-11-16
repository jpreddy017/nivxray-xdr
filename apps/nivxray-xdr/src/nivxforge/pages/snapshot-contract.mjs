export const pending = status => ['QUEUED', 'RUNNING'].includes(status);
export const completed = status => ['COMPLETED_WITH_ROWS', 'COMPLETED_ZERO_ROWS', 'COMPLETED_PARTIAL'].includes(status);
export function scoped(data, tenant) {
  if (!tenant || data?.tenant_id !== tenant) throw new Error('Snapshot response does not belong to the selected customer. Refresh and retry.');
  return data;
}
export function snapshotError(error) {
  const detail = error?.response?.data?.detail;
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) return detail.map(x => x.msg || 'Invalid input').join('; ');
  if (detail && typeof detail === 'object') return detail.reason || detail.message || detail.error || 'Request refused.';
  return error?.message || 'Snapshot service unavailable. Retry the request.';
}
export function coverage(job) {
  const captured = completed(job?.status);
  return [{name:'Running processes', state:captured ? (job.rows_truncated ? 'PARTIAL' : 'COLLECTED') : 'NOT_COLLECTED', note:captured ? 'Sensor-reported PID, name and executable path; unreadable paths remain unknown.' : 'No completed capture is available.'},
    ...['System and installed software','Services and scheduled tasks','Startup and persistence','Network connections, listeners and DNS','Users and logon sessions','Loaded modules and hashes','Disk encryption and mounted drives','Registry and execution artifacts','Browser and shell history'].map(name=>({name,state:'NOT_SUPPORTED',note:'Not collected by the current process-snapshot profile.'}))];
}
export function validateJob(data, tenant, id) {
  scoped(data, tenant);
  if (data.job_id !== id || !Array.isArray(data.rows)) throw new Error('Invalid snapshot evidence response.');
  if (data.categories != null && (!Array.isArray(data.categories) || data.categories.some(c => !c || typeof c.category_id !== 'string' || !Array.isArray(c.rows) || (c.issues != null && (!Array.isArray(c.issues) || c.issues.some(i => typeof i !== 'string')))))) throw new Error('Invalid category evidence response.');
  return data;
}
