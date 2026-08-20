// Lane-A proving-ground route.
// The real product surface is the "EVIDENCE" tab inside ThreatAnalysis
// (WorkspacePage).  This route is kept as a standalone entry point
// while the T2 wire contract is being validated, and can be removed
// once the Workspace tab is blessed by the owner.
import StructuredEvidenceTab from "@/components/StructuredEvidenceTab";

export default function LaneAWorkspacePage() {
    return (
        <div
            data-testid="lane-a-workspace"
            className="min-h-screen bg-slate-950 text-slate-100">
            <div className="max-w-7xl mx-auto p-6 space-y-4">
                <header className="border-b border-slate-800 pb-4">
                    <h1 className="text-2xl font-semibold tracking-tight">
                        Lane A · Structured Evidence
                    </h1>
                    <p className="text-sm text-slate-400 mt-1">
                        NDJSON / JSON / CSV / XML → LogicalEvents. Aggregation only;
                        correlation happens later in ICE. Same component powers the
                        Workspace "Evidence" tab.
                    </p>
                </header>
                <StructuredEvidenceTab />
            </div>
        </div>
    );
}
