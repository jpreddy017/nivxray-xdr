/**
 * CommandHubPage — production route (/command-hub).
 *
 * Wraps the design-preview Command Hub layout in the site's global
 * Header so analysts can navigate back to Workspace / Dashboard /
 * other tabs. The preview route (/preview/command-hub) remains
 * un-authed for design iteration.
 */
import Header from "@/components/Header";
import PreviewCommandHub from "@/pages/PreviewCommandHub";

export default function CommandHubPage() {
  return (
    <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column" }}>
      <Header />
      <div style={{ flex: 1, minHeight: 0 }}>
        <PreviewCommandHub />
      </div>
    </div>
  );
}
