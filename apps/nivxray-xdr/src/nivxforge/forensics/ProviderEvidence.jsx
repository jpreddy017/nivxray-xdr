import React from 'react';

export function reputationLabel(provider) {
  if (!provider) return 'Pending';
  const labels={not_configured:'Not configured',not_applicable:'Not applicable',
    no_record:'No provider record',authentication_failed:'Provider authentication failed',
    access_denied:'Provider access denied',rate_limited:'Provider rate limit reached',
    unavailable:'Provider unavailable',invalid_response:'Invalid provider response',
    configuration_unavailable:'Provider configuration unavailable',lookup_failed:'Lookup failed',
    detections_reported:'Detections reported',suspicious:'Suspicious engine reports',
    abuse_reported:'Abuse reported',listed_by_provider:'Listed by provider',unknown:'Unknown'};
  const state=provider.status==='available'?provider.disposition:provider.status;
  return labels[state]||'Unknown';
}

export default function ProviderEvidence({provider}) {
  const reports=provider?.reports||[];
  return <>
    {provider?.observed_at!=null && <p>Provider observation: {String(provider.observed_at)}</p>}
    {reports.length>0 && <details><summary>Supporting reports ({reports.length})</summary>
      <ul>{reports.map((report,index)=><li key={index}>
        {report.name && <strong>{report.name}</strong>}
        {report.pulse_id && <div>Pulse: {report.pulse_id}</div>}
        {report.scan_id && <div>Scan: {report.scan_id}</div>}
        {report.observed_at && <div>Observed: {report.observed_at}</div>}
        {report.first_seen && <div>First seen: {report.first_seen}</div>}
        {report.last_seen && <div>Last seen: {report.last_seen}</div>}
        {report.confidence!=null && <div>Provider confidence: {report.confidence}</div>}
        {report.url_status && <div>URL status: {report.url_status}</div>}
        {report.tags?.length>0 && <div>Research tags: {report.tags.join(', ')}</div>}
      </li>)}</ul>
    </details>}
  </>;
}
