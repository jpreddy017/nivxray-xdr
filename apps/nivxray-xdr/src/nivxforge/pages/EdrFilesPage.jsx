import React from "react";
import NivXForgeConsole from "@/nivxforge/NivXForgeConsole";
import GlobalFileSearch from "@/nivxforge/files/GlobalFileSearch";

export default function EdrFilesPage() {
  return <NivXForgeConsole activeTab="files">
    <h1 className="page-h1">Files</h1>
    <GlobalFileSearch />
  </NivXForgeConsole>;
}
