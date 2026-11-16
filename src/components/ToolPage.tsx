import type { ReactNode } from "react";
import type { Tool } from "../app/tools";

/* =========================
   Tool Page
   ========================= */

/* Shared frame for every tool: header, privacy note, then the tool's content. */
export default function ToolPage({ tool, children }: { tool: Tool; children: ReactNode }) {
  return (
    <>
      <header className="page-header">
        <h1>{tool.label}</h1>
        <p>{tool.summary}</p>
      </header>

      <p className="notice">{tool.privacy}</p>

      {children}
    </>
  );
}
