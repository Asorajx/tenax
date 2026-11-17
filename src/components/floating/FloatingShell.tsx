import { useEffect, useRef, type ReactNode } from "react";
import { workspaceOf, WORKSPACES } from "../../app/workspaces";
import TitleBar from "./TitleBar";
import WorkspaceSwitcher from "./WorkspaceSwitcher";

/* =========================
   Floating Shell
   ========================= */

interface FloatingShellProps {
  /* The page that is showing: "home", "settings" or a tool. */
  page: string;
  onNavigate: (page: string) => void;
  /* The tool to open for a workspace, which is the one that was last open in it. */
  toolFor: (workspace: string) => string;
  /* The pages, already rendered. The shell only frames them. */
  children: ReactNode;
}

/* One seamless window: the title bar, which holds the navigation, and the content below it. The classic */
/* sidebar layout is not used here, and none of the tools know which layout they are in. */
export default function FloatingShell({ page, onNavigate, toolFor, children }: FloatingShellProps) {
  const workspace = workspaceOf(page);

  /* A workspace with one tool has nothing to switch between, so it gets no tab bar. */
  const tabbed = workspace !== undefined && workspace.tools.length > 1;
  const content = useRef<HTMLElement>(null);

  /* Each newly shown page starts scrolled to the top. */
  useEffect(() => {
    content.current?.scrollTo(0, 0);
  }, [page]);

  function select(id: string) {
    onNavigate(WORKSPACES.some((candidate) => candidate.id === id) ? toolFor(id) : id);
  }

  /* data-ws colours the parts that belong to the workspace you are in. */
  return (
    <div className="floating-shell" data-ws={workspace?.id ?? page}>
      <TitleBar current={workspace?.id ?? page} onSelect={select} />

      {workspace && tabbed && (
        <WorkspaceSwitcher
          label={`Tools in ${workspace.label}`}
          tabs={workspace.tools}
          active={page}
          onSelect={onNavigate}
        />
      )}

      <main className="floating-content" data-switcher={tabbed ? "true" : undefined} ref={content}>
        {children}
      </main>
    </div>
  );
}
