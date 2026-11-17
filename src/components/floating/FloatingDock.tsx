import type { KeyboardEvent } from "react";
import { Globe, House, Settings, type LucideIcon } from "lucide-react";
import { useNetwork } from "../../app/network";
import { WORKSPACES } from "../../app/workspaces";

/* =========================
   Floating Dock
   ========================= */

interface ItemProps {
  label: string;
  icon: LucideIcon;
  /* What the hover label says, when it is not just the label. */
  tip?: string;
  active?: boolean;
  /* For a switch, whether it is on. Leave out for an ordinary button. */
  checked?: boolean;
  /* Whether the name is written beside the icon at normal widths. Items without it are icons only. */
  labelled?: boolean;
  /* The colour of the workspace the item opens, used while it is the one showing. */
  workspace?: string;
  onClick: () => void;
  /* A small dot on the icon, lit when true. Leave out for no dot. */
  dot?: boolean;
}

/* One icon. Its name is written beside it when there is room. Otherwise it shows on hover or keyboard */
/* focus, under the icon. The icon and name settle a few pixels lower under the cursor and on focus. */
function Item({ label, icon: Icon, tip, active, checked, labelled, workspace, onClick, dot }: ItemProps) {
  return (
    <button
      type="button"
      className="dock-item"
      data-labelled={labelled ? "true" : undefined}
      data-workspace={workspace}
      aria-label={label}
      aria-current={active ? "page" : undefined}
      role={checked === undefined ? undefined : "switch"}
      aria-checked={checked}
      onClick={onClick}
    >
      <span className="dock-inner">
        <span className="dock-icon">
          <Icon size={17} strokeWidth={1.75} aria-hidden="true" />
          {dot !== undefined && <span className="dock-dot" data-on={dot ? "true" : undefined} aria-hidden="true" />}
        </span>
        {labelled && (
          <span className="dock-label" aria-hidden="true">
            {label}
          </span>
        )}
      </span>
      <span className="dock-tip" aria-hidden="true">
        {tip ?? label}
      </span>
    </button>
  );
}

interface FloatingDockProps {
  /* "home", "settings", or the id of the workspace that is showing. */
  current: string;
  onSelect: (id: string) => void;
}

/* The navigation, in the title bar. It has no background of its own. The places to go are at the left, */
/* and Network access and Settings are at the right. The space between them can still drag the window. */
export default function FloatingDock({ current, onSelect }: FloatingDockProps) {
  const { enabled, setEnabled } = useNetwork();

  /* Left and Right move between the icons. */
  function onKeyDown(event: KeyboardEvent<HTMLElement>) {
    if (event.key !== "ArrowRight" && event.key !== "ArrowLeft") return;
    const items = [...event.currentTarget.querySelectorAll<HTMLButtonElement>(".dock-item")];
    const index = items.indexOf(document.activeElement as HTMLButtonElement);
    const next = items[index + (event.key === "ArrowRight" ? 1 : -1)];
    if (next) {
      event.preventDefault();
      next.focus();
    }
  }

  return (
    <nav className="dock" aria-label="Main" data-tauri-drag-region onKeyDown={onKeyDown}>
      <div className="dock-group" data-tauri-drag-region>
        <Item label="Home" icon={House} labelled active={current === "home"} onClick={() => onSelect("home")} />
        {WORKSPACES.map((workspace) => (
          <Item
            key={workspace.id}
            label={workspace.label}
            icon={workspace.icon}
            labelled
            workspace={workspace.id}
            active={current === workspace.id}
            onClick={() => onSelect(workspace.id)}
          />
        ))}
      </div>

      <div className="dock-group dock-end" data-tauri-drag-region>
        <Item
          label="Network access"
          tip={`Network access: ${enabled ? "On" : "Off"}`}
          icon={Globe}
          checked={enabled}
          dot={enabled}
          onClick={() => setEnabled(!enabled)}
        />
        <Item label="Settings" icon={Settings} active={current === "settings"} onClick={() => onSelect("settings")} />
      </div>
    </nav>
  );
}
