/**
 * NivXForge · Layout wrapper. Renders the app Header at the top, then
 * splits the viewport into a persistent left Sidebar + right content column.
 *
 * Every /nivxforge/* page renders inside this layout. Purely presentational.
 */
import Header from "../../components/Header";
import NivxForgeSidebar from "./NivxForgeSidebar";

const S = {
  outer: { minHeight: "100vh", background: "var(--bg)" },
  split: { display: "flex", alignItems: "stretch" },
  main:  { flex: 1, minWidth: 0 },
};

export default function NivxForgeLayout({ children }) {
  return (
    <div style={S.outer}>
      <Header />
      <div style={S.split}>
        <NivxForgeSidebar />
        <main style={S.main} data-testid="nivxforge-main">
          {children}
        </main>
      </div>
    </div>
  );
}
