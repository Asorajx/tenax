import { TOOL_GROUPS } from "../app/tools";

/* =========================
   Home
   ========================= */

export default function Home({ onNavigate }: { onNavigate: (page: string) => void }) {
  return (
    <>
      <header className="page-header">
        <h1>Home</h1>
        <p>
          Tenax explains what it finds, why it matters and what to do next. It does not give
          security scores or promise that anything is safe.
        </p>
      </header>

      {TOOL_GROUPS.map((group) => (
        <section key={group.id} className="section">
          <h2>{group.label}</h2>
          <div className="panel">
            {group.tools.map((tool) => (
              <button key={tool.id} type="button" className="row" onClick={() => onNavigate(tool.id)}>
                <span className="row-text">
                  <span className="row-title">{tool.label}</span>
                  <span>{tool.summary}</span>
                </span>
                <span className="row-meta" data-ready={tool.ready}>
                  {tool.ready ? "Available" : "Planned"}
                </span>
              </button>
            ))}
          </div>
        </section>
      ))}
    </>
  );
}
