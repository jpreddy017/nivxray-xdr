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
