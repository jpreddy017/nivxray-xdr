import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { commandRequest, validateCommandResult } from "../commandIntelligenceContract";
vi.mock("@/lib/api", () => ({ default: { post: vi.fn() } }));
vi.mock("@/xdr/XdrShell", () => ({ default: ({children}) => children }));
import { CommandResult } from "../XdrCommandIntelPage";
const report = {
  schema_version: "command-intelligence/1", original_command: "  whoami\n", engine_version:"test",
  decode_status:"PARTIALLY_RECOVERED", decode_status_reason:"Unknown layer remains",
  canonical_decoded_artifact:{promoted:false,reason:"Partial"},
  final_recoverable:{format:"text",value:"<script>alert(1)</script>"},
  candidates:[], detected_methods:["base64"], warnings:["Depth limit"], unresolved_portions:["Unresolved test expression"], behaviors:[], iocs:[], mitre_status:"HELD",
};
describe("Automatic Command Intelligence", () => {
  it("preserves exact input and enables existing API automatic mode", () => {
    expect(commandRequest("  whoami\n")).toEqual({input:"  whoami\n",automatic:true});
  });
  it("enforces UTF-8 byte and blank input limits", () => {
    expect(() => commandRequest(" ")).toThrow();
    expect(() => commandRequest("é".repeat(8193))).toThrow(/16 KiB/);
  });
  it("fails visibly on old, empty or mismatched backend responses", () => {
    for (const data of [null, {}, {...report, original_command:"other"}, {...report, unresolved_portions:undefined}]) expect(() => validateCommandResult(data, "  whoami\n")).toThrow(/compatible/);
    expect(validateCommandResult(report, "  whoami\n")).toBe(report);
  });
  it("rejects the observed legacy-style 200 response even when a candidate contains output", () => {
    const original = 'powershell -NoProfile -Command "Write-Output \'NivXRay-Test-123\'"';
    // Minimal reproduction of the observed field shape, not an automatic report.
    const legacy = {original_command:original, parsed_structure:{interpreter:"powershell"},
      decode_status:"FAILED", decode_chains:[{final_output:"",chains:[{steps:[],output:"Write-Output 'NivXRay-Test-123'"}]}],
      behaviors:[{tag:"stealth-flags",detail:"High-risk interpreter switches: -noprofile, -nop"}],
      iocs:{urls:[],domains:[],ips:[]}};
    const before = JSON.stringify(legacy);
    expect(commandRequest(original)).toEqual({input:original,automatic:true});
    expect(() => validateCommandResult(legacy,original)).toThrow(/compatible automatic analysis report/);
    expect(JSON.stringify(legacy)).toBe(before);
  });
  it("renders evidence as escaped text and partial output as noncanonical", () => {
    const html = renderToStaticMarkup(<CommandResult result={report}/>);
    expect(html).toContain("not canonical");
    expect(html).toContain("Depth limit");
    expect(html).toContain("Unresolved limitations");
    expect(html).toContain("Unresolved test expression");
    expect(html).toContain("&lt;script&gt;");
    expect(html).not.toContain("<script>");
    expect(html).toContain("HELD");
  });
  it("distinguishes binary evidence from script", () => {
    const html = renderToStaticMarkup(<CommandResult result={{...report,final_recoverable:{format:"base64",value:"AAAA"}}}/>);
    expect(html).toContain("Binary evidence");
    expect(html).toContain("not a decoded script");
  });
});

it("renders typed behavioral evidence with exact source offsets", () => {
  const behaviors=[{kind:"download_and_evaluate",basis:"correlated_syntax",explanation:"Retrieval expression supplied to evaluation; execution not established.",match:"IEX (Invoke-WebRequest)",evidence_id:"sha256:observed",start:0,end:23,execution_proven:false}];
  const html=renderToStaticMarkup(<CommandResult result={{...report,behaviors}}/>);
  expect(html).toContain("download and evaluate");
  expect(html).toContain("correlated syntax");
  expect(html).toContain("characters 0–23");
  expect(html).toContain("sha256:observed");
});
