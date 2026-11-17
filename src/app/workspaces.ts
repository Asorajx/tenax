import { useCallback, useEffect, useState } from "react";
import { KeyRound, Laptop, ScanSearch, Network, type LucideIcon } from "lucide-react";
import { TOOL_GROUPS, type Tool } from "./tools";

/* =========================
   Workspaces
   ========================= */

/* A workspace groups related tools. Its tools come from the same list as everywhere else, so there is */
/* still one place that says which tools exist. */
export interface Workspace {
  id: string;
  label: string;
  icon: LucideIcon;
  /* One line for the Home screen. */
  summary: string;
  tools: Tool[];
  /* Whether its tools use the network, shown beside it when the navigation is expanded. */
  network?: Tool["network"];
}

/* The order here is the order in the navigation and for Ctrl + 2 to 5. */
const DEFINITIONS: { id: string; label: string; icon: LucideIcon; group: string; summary: string }[] = [
  { id: "investigate", label: "Investigate", icon: ScanSearch, group: "phishing", summary: "Look into an email or a link." },
  { id: "network", label: "Network", icon: Network, group: "network", summary: "Look into a domain, an address or a certificate." },
  { id: "passwords", label: "Passwords", icon: KeyRound, group: "password", summary: "See how strong a password is and whether it has leaked." },
  { id: "device", label: "Device", icon: Laptop, group: "device", summary: "Review the security settings on this PC." },
];

export const WORKSPACES: Workspace[] = DEFINITIONS.map((definition): Workspace => {
  const tools = TOOL_GROUPS.find((group) => group.id === definition.group)?.tools ?? [];
  const using = tools.filter((tool) => tool.network).length;
  return {
    id: definition.id,
    label: definition.label,
    icon: definition.icon,
    summary: definition.summary,
    tools,
    /* Every tool uses it, at least sometimes, so the workspace is marked as needing it. */
    network: using === 0 ? undefined : using === tools.length ? "required" : "optional",
  };
}).filter((workspace) => workspace.tools.length > 0);

/* The workspace a tool belongs to, if it has one. */
export function workspaceOf(toolId: string): Workspace | undefined {
  return WORKSPACES.find((workspace) => workspace.tools.some((tool) => tool.id === toolId));
}

/* Remembers which tool was open in each workspace, so opening a workspace again shows the same one. */
/* The first time, it is the workspace's first tool, which is the URL Checker for Investigate. */
export function useLastTools(page: string) {
  const [last, setLast] = useState<Record<string, string>>({});
  const workspace = workspaceOf(page)?.id;

  useEffect(() => {
    if (workspace) setLast((known) => (known[workspace] === page ? known : { ...known, [workspace]: page }));
  }, [workspace, page]);

  return useCallback(
    (workspaceId: string) => last[workspaceId] ?? WORKSPACES.find((w) => w.id === workspaceId)?.tools[0].id ?? "home",
    [last],
  );
}
