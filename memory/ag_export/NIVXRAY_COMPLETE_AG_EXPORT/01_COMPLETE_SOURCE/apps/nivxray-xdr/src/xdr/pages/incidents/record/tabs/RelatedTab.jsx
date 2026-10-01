/**
 * RelatedTab · Layer 3 · cross-incident and cross-entity links.
 *
 * A cross-incident correlation API is on the Phase-4 backlog.  This
 * tab renders an honest empty state so analysts see the surface but
 * no fabricated relationships appear.  Once the correlation engine
 * projects `/api/xdr/incidents/:id/related`, this tab will bind to it.
 */
import React from "react";

export default function RelatedTab({ incident }) {
  const hosts = incident.assets?.hosts || incident.hosts || [];
  const users = incident.assets?.users || incident.users || [];

  return (
    <div data-testid="xdr-record-related">
      <div className="rl-section">
        <div className="rl-section-title">Related incidents</div>
        <div className="rl-empty" data-testid="xdr-record-related-empty">
          NOT AVAILABLE — the cross-incident correlation projection
          arrives with Phase 4.  This surface will list incidents that
          share IOCs, techniques or affected entities.
          <span className="kbd">/api/xdr/incidents/:id/related · reserved · Phase 4</span>
        </div>
      </div>

      <div className="rl-section">
        <div className="rl-section-title">Related entities (from this case)</div>
        {(hosts.length + users.length) === 0
          ? <div className="rl-empty">
              NO EVIDENCE — no host or user entities have been projected
              onto this incident yet.
            </div>
          : <div className="rl-metric-grid">
              <div className="rl-metric info">
                <div className="k">Hosts</div>
                <div className="v">{hosts.length}</div>
                {hosts.length > 0 && (
                  <div className="sub" title={hosts.map(h => h.host_id || h.name).join(", ")}>
                    {(hosts[0]?.host_id || hosts[0]?.name || "").toString().slice(0, 24)}
                    {hosts.length > 1 && ` +${hosts.length - 1}`}
                  </div>
                )}
              </div>
              <div className="rl-metric info">
                <div className="k">Users</div>
                <div className="v">{users.length}</div>
                {users.length > 0 && (
                  <div className="sub" title={users.map(u => u.user_id || u.email).join(", ")}>
                    {(users[0]?.user_id || users[0]?.email || "").toString().slice(0, 24)}
                    {users.length > 1 && ` +${users.length - 1}`}
                  </div>
                )}
              </div>
            </div>}
      </div>
    </div>
  );
}
