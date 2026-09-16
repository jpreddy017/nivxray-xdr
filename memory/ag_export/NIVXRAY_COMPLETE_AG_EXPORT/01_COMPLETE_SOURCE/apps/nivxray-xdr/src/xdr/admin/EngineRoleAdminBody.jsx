/**
 * EngineRoleAdminBody — reusable admin surface for any Engine Role.
 *
 * Consumes:
 *   GET /api/admin/content-supply-chain/engines/list?role={ROLE}
 *   GET /api/admin/content-supply-chain/contracts?classification={ROLE}
 *
 * Renders:
 *   • AdminHero with role-specific stats (implementations, states,
 *     contract statuses)
 *   • Two-column table: implementation | module path
 *   • Contract badges per implementation (CONTRACT_DECLARED /
 *     RUNTIME_VERIFIED / EXECUTION_VERIFIED)
 *
 * Nothing is invented — every row is a real backend record.
 */
import React, { useEffect, useState } from "react";
import { RefreshCcw } from "lucide-react";
import api from "@/lib/api";
import AdminHero from "@/xdr/admin/AdminHero";


// Rewrite the top of ParsersBody to import from here.
export default function EngineRoleAdminBody({
  role, eyebrow, title, subtitle, icon, testid, emptyCopy,
}) {
  const [engines,   setEngines]   = useState([]);
  const [contracts, setContracts] = useState([]);
  const [err,       setErr]       = useState(null);
  const [tick,      setTick]      = useState(0);

  useEffect(() => {
    (async () => {
      try {
        setErr(null);
        const [er, cr] = await Promise.all([
          api.get(`/admin/content-supply-chain/engines/list?role=${role}&limit=500`),
          api.get(`/admin/content-supply-chain/contracts?classification=${role}&limit=500`),
        ]);
        setEngines(er?.data?.items || []);
        setContracts(cr?.data?.items || []);
      } catch (e) {
        setErr(e?.response?.data?.detail || e?.message || "load failed");
      }
    })();
  }, [role, tick]);

  // Index contracts by engine_id for O(1) lookup
  const cByEngine = React.useMemo(() => {
    const m = {};
    for (const c of contracts) m[c.engine_id] = c;
    return m;
  }, [contracts]);

  // Status rollup — honest zero when empty
  const totalImpl   = engines.length;
  const totalContr  = contracts.length;
  const nDeclared   = contracts.filter((c) => c.contract_status === "CONTRACT_DECLARED").length;
  const nRuntime    = contracts.filter((c) => c.contract_status === "RUNTIME_VERIFIED").length;
  const nExecVerif  = contracts.filter((c) => c.contract_status === "EXECUTION_VERIFIED").length;
  const detectionOn = contracts.filter((c) => c?.execution?.detection).length;

  const stats = [
    { label: "Implementations",   value: totalImpl,
      testid: `${testid}-stat-impl` },
    { label: "Contracts",         value: totalContr,
      testid: `${testid}-stat-contracts` },
    { label: "Declared",          value: nDeclared,
      testid: `${testid}-stat-declared` },
    { label: "Runtime verified",  value: nRuntime, color: "var(--mint)",
      testid: `${testid}-stat-runtime` },
    { label: "Execution verified", value: nExecVerif, color: "var(--mint)",
      testid: `${testid}-stat-exec` },
    { label: "Detection capable", value: detectionOn,
      color: detectionOn ? "var(--mint)" : undefined,
      testid: `${testid}-stat-detect` },
  ];

  return (
    <div data-testid={`${testid}-body`}>
      <AdminHero
        icon={icon}
        eyebrow={eyebrow}
        title={title}
        subtitle={subtitle}
        source={`/api/admin/content-supply-chain/engines/list?role=${role}`}
        stats={stats}
        testid={`${testid}-hero`}
        actions={
          <button className="btn ghost"
                      onClick={() => setTick((n) => n + 1)}
                      data-testid={`${testid}-refresh`}
                      style={{ padding: "3px 10px", fontSize: 11 }}>
            <RefreshCcw size={11} /> Refresh
          </button>
        }
      />

      {err && (
        <div className="panel" data-testid={`${testid}-error`}
                style={{ padding: 12, marginBottom: 10,
                            borderLeft: "3px solid #f87171" }}>
          <div style={{ fontFamily: "var(--mono)", fontSize: 11,
                              color: "#f87171" }}>
            error · {err}
          </div>
        </div>
      )}

      {totalImpl === 0 && !err && (
        <div className="panel" data-testid={`${testid}-empty`}
                style={{ padding: 16, textAlign: "center",
                            color: "var(--faint)", fontSize: 12,
                            fontFamily: "var(--mono)" }}>
          {emptyCopy}
        </div>
      )}

      {totalImpl > 0 && (
        <div className="panel" data-testid={`${testid}-table`}
                  style={{ padding: 0, overflow: "hidden" }}>
          <table style={{ width: "100%", borderCollapse: "collapse",
                                fontSize: 11.5 }}>
            <thead>
              <tr style={{
                background: "var(--panel2)",
                borderBottom: "1px solid var(--border)",
              }}>
                <Th>Implementation</Th>
                <Th>Module</Th>
                <Th>Scope</Th>
                <Th>Contract</Th>
                <Th>Detection</Th>
              </tr>
            </thead>
            <tbody>
              {engines.map((e) => {
                const c = cByEngine[e.engine_id];
                const cs = c?.contract_status || "—";
                const det = c?.execution?.detection;
                return (
                  <tr key={e.engine_id}
                          data-testid={`${testid}-row-${e.engine_id}`}
                          style={{ borderBottom: "1px solid var(--border)" }}>
                    <Td mono>{e.canonical_name}</Td>
                    <Td mono dim>{e.module}</Td>
                    <Td mono dim>{e.scope}</Td>
                    <Td><ContractChip status={cs} /></Td>
                    <Td>
                      {det === true
                        ? <Chip color="var(--mint)">YES</Chip>
                        : <Chip color="var(--faint)">no</Chip>}
                    </Td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}


function Th({ children }) {
  return <th style={{
    textAlign: "left", padding: "8px 12px",
    fontFamily: "var(--mono)", fontSize: 9.5,
    letterSpacing: ".4px", fontWeight: 700,
    color: "var(--faint)", textTransform: "uppercase",
  }}>{children}</th>;
}


function Td({ children, mono, dim }) {
  return <td style={{
    padding: "7px 12px",
    fontFamily: mono ? "var(--mono)" : "var(--sans)",
    fontSize: 11.5,
    color: dim ? "var(--text-dim)" : "var(--text)",
    verticalAlign: "middle",
  }}>{children}</td>;
}


function Chip({ children, color }) {
  return <span style={{
    fontFamily: "var(--mono)", fontSize: 9.5, fontWeight: 700,
    padding: "2px 6px", border: `1px solid ${color}`,
    borderRadius: 3, color, letterSpacing: ".3px",
  }}>{children}</span>;
}


function ContractChip({ status }) {
  const color =
    status === "EXECUTION_VERIFIED" ? "var(--mint)" :
    status === "RUNTIME_VERIFIED"   ? "var(--mint)" :
    status === "CONTRACT_DECLARED"  ? "var(--cyan)" :
    "var(--faint)";
  return <Chip color={color}>{status}</Chip>;
}
