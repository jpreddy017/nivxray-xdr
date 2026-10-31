// Navigation hints never grant access; the destination API reauthorizes them.
export function resolveTrajectoryTarget(rows, { deviceIid, device, incidentId }) {
  const ref = deviceIid || device;
  const needle = String(ref || '').trim().toLowerCase();
  const matches = rows.filter(row => {
    if (ref) {
      const fields = deviceIid ? ['device_iid'] : ['device_iid', 'device_ref', 'endpoint_id', 'hostname'];
      return fields.some(key => String(row[key] || '').toLowerCase() === needle);
    }
    return incidentId && ((row.case_ids || []).includes(incidentId) || row.latest_incident_id === incidentId);
  });
  // Neither first-match nor unrelated-incident fallback proves device identity.
  if (matches.length !== 1) return null;
  return matches[0].device_ref || matches[0].device_iid || matches[0].endpoint_id || null;
}

export function trajectoryDestination(params, device, hash = '') {
  const query = new URLSearchParams(params);
  query.delete('device_iid');
  query.delete('endpoint_id');
  query.set('device', device);
  return `/edr/device-trajectory?${query.toString()}${hash}`;
}
