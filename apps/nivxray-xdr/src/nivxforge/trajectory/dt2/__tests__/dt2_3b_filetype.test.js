import { describe, expect, it } from "vitest";

import { CISCO_DISPLAYED, OTHER, fileTypeOf } from "../fileType";
import { axisRowsOf, ROW_FILE } from "../graphModel";

describe("Cisco's documented displayed file types (User Guide p.401)", () => {
  it("classifies the ten documented classes from the observed path", () => {
    expect(fileTypeOf("C:\\Users\\Public\\payload.exe")).toBe("EXECUTABLE");
    expect(fileTypeOf("C:\\x\\report.pdf")).toBe("PDF");
    expect(fileTypeOf("C:\\x\\driver.cab")).toBe("CABINET");
    expect(fileTypeOf("C:\\x\\invoice.docm")).toBe("OFFICE");
    expect(fileTypeOf("C:\\x\\loot.zip")).toBe("ARCHIVE");
    expect(fileTypeOf("C:\\x\\banner.swf")).toBe("FLASH");
    expect(fileTypeOf("C:\\x\\notes.txt")).toBe("TEXT");
    expect(fileTypeOf("C:\\x\\memo.rtf")).toBe("RICHTEXT");
    expect(fileTypeOf("C:\\x\\stage.ps1")).toBe("SCRIPT");
    expect(fileTypeOf("C:\\x\\setup.msi")).toBe("INSTALLER");
  });

  it("puts a browser cache artefact outside the displayed set", () => {
    for (const p of ["...\\leveldb\\001425.ldb", "...\\009034.log",
                     "...\\41c0c39f.tmp", "...\\nodot"]) {
      expect(fileTypeOf(p)).toBe(OTHER);
    }
  });

  const graph = () => {
    const act = (id, label) => ({
      node_id: id, node_type: "ACTIVITY", family: "FILE", kind: "file_write",
      label, process_node_id: "pnode:p", edge_id: `e:${id}`,
      times: { source_time: "2026-09-22 15:48:36.697" },
    });
    return {
      process_nodes: [{ node_id: "pnode:p", node_type: "PROCESS", depth: 0,
                        label: "chrome.exe",
                        lifeline: { first_evidence_at: "2026-09-22 15:43:31.770",
                                    last_evidence_at: "2026-09-22 15:52:41.916" } }],
      activity_nodes: [act("a1", "C:\\x\\payload.exe"),
                       act("a2", "C:\\x\\001425.ldb")],
      edges: [{ edge_id: "e:a1", relationship_type: "PROCESS_FILE",
                source_node_id: "pnode:p", target_node_id: "a1" },
              { edge_id: "e:a2", relationship_type: "PROCESS_FILE",
                source_node_id: "pnode:p", target_node_id: "a2" }],
      root_node_ids: ["pnode:p"],
    };
  };

  it("draws only the selected classes on the axis", () => {
    const rows = axisRowsOf(graph(), { fileTypes: new Set(CISCO_DISPLAYED) });
    const files = rows.filter((r) => r.kind === ROW_FILE);
    expect(files).toHaveLength(1);
    expect(files[0].node.label).toContain("payload.exe");
  });

  it("shows the other class when the analyst selects it", () => {
    const rows = axisRowsOf(graph(),
                            { fileTypes: new Set([...CISCO_DISPLAYED, OTHER]) });
    expect(rows.filter((r) => r.kind === ROW_FILE)).toHaveLength(2);
  });

  it("without a selection nothing is filtered — no silent hiding", () => {
    expect(axisRowsOf(graph()).filter((r) => r.kind === ROW_FILE))
      .toHaveLength(2);
  });
});
