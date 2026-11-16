import type { Tool } from "../app/tools";
import ToolPage from "../components/ToolPage";

/* =========================
   Planned Tool
   ========================= */

/* Placeholder page for tools that are not built yet. */
export default function PlannedTool({ tool }: { tool: Tool }) {
  return (
    <ToolPage tool={tool}>
      <div className="empty-state">
        <h3>Not built yet</h3>
        <p>This tool is planned. When it is ready it will check:</p>
        <ul>
          {tool.plan.map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
      </div>
    </ToolPage>
  );
}
