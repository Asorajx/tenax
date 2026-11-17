import { useLayoutEffect, useRef, useState, type KeyboardEvent } from "react";
import type { Tool } from "../../app/tools";
import NetworkIndicator from "../NetworkIndicator";

/* =========================
   Workspace Switcher
   ========================= */

export interface SwitcherTab {
  id: string;
  label: string;
  /* Shown beside a tool's name when it uses the network. */
  network?: Tool["network"];
}

interface WorkspaceSwitcherProps {
  /* What the tabs are, read out by screen readers, such as "Tools in Network". */
  label: string;
  tabs: SwitcherTab[];
  /* The tab that is showing. */
  active: string;
  onSelect: (id: string) => void;
}

/* A compact row of tabs, for the tools in a workspace. Left and Right move */
/* between them. The workspace itself is already shown in the navigation above, so it is not named again. */
export default function WorkspaceSwitcher({ label, tabs: items, active, onSelect }: WorkspaceSwitcherProps) {
  /* One underline glides to the chosen tab, instead of each tab drawing its own. */
  const tabs = useRef<HTMLDivElement>(null);
  const [line, setLine] = useState<{ left: number; width: number }>();
  useLayoutEffect(() => {
    function place() {
      const tab = tabs.current?.querySelector<HTMLElement>("[aria-selected=true]");
      if (tab) setLine({ left: tab.offsetLeft, width: tab.offsetWidth });
    }
    place();
    window.addEventListener("resize", place);
    return () => window.removeEventListener("resize", place);
  }, [active, label]);

  function onKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    if (event.key !== "ArrowRight" && event.key !== "ArrowLeft") return;

    const tabs = [...event.currentTarget.querySelectorAll<HTMLButtonElement>("[role=tab]")];
    const index = tabs.indexOf(document.activeElement as HTMLButtonElement);
    const next = tabs[(index + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length];
    event.preventDefault();
    next.focus();
    next.click();
  }

  return (
    <div className="switcher">
      <div ref={tabs} className="switcher-tabs" role="tablist" aria-label={label} onKeyDown={onKeyDown}>
        {items.map((tool) => (
          <button
            key={tool.id}
            type="button"
            role="tab"
            className="switcher-tab"
            aria-selected={tool.id === active}
            tabIndex={tool.id === active ? 0 : -1}
            onClick={() => onSelect(tool.id)}
          >
            {tool.label}
            {tool.network && <NetworkIndicator level={tool.network} />}
          </button>
        ))}
        {line && <span className="switcher-line" style={{ transform: `translateX(${line.left}px)`, width: line.width }} aria-hidden="true" />}
      </div>
    </div>
  );
}
