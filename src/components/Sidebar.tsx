import type { KeyboardEvent } from "react";
import { TOOL_GROUPS } from "../app/tools";

/* =========================
   Sidebar
   ========================= */

interface SidebarProps {
  page: string;
  onNavigate: (page: string) => void;
}

/* Up and Down move focus between sidebar items. */
function moveFocus(event: KeyboardEvent<HTMLElement>) {
  if (event.key !== "ArrowDown" && event.key !== "ArrowUp") return;

  const items = [...event.currentTarget.querySelectorAll<HTMLButtonElement>(".nav-item")];
  const index = items.indexOf(document.activeElement as HTMLButtonElement);
  const next = items[index + (event.key === "ArrowDown" ? 1 : -1)];
  if (next) {
    event.preventDefault();
    next.focus();
  }
}

export default function Sidebar({ page, onNavigate }: SidebarProps) {
  const item = (id: string, label: string) => (
    <button
      key={id}
      type="button"
      className="nav-item"
      aria-current={page === id ? "page" : undefined}
      onClick={() => onNavigate(id)}
    >
      {label}
    </button>
  );

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        {/* Same shapes as assets/tenax-icon.svg, coloured by the theme. */}
        <svg className="sidebar-mark" viewBox="11 12 42 41" aria-hidden="true">
          <path
            className="sidebar-mark-shield"
            d="M14 21H50L48.2 32.3C46.8 40.8 40.5 48.1 32 53C23.5 48.1 17.2 40.8 15.8 32.3L14 21Z"
          />
          <path fill="currentColor" d="M11 12H53V21.5H11Z M27 21H37V41.5L32 47.5L27 41.5Z" />
        </svg>
        Tenax
      </div>

      <nav className="sidebar-nav" aria-label="Main" onKeyDown={moveFocus}>
        {item("home", "Home")}

        {TOOL_GROUPS.map((group) => (
          <div key={group.id} className="sidebar-group">
            <h2>{group.label}</h2>
            {group.tools.map((tool) => item(tool.id, tool.label))}
          </div>
        ))}

        <div className="sidebar-footer">{item("settings", "Settings")}</div>
      </nav>
    </aside>
  );
}
