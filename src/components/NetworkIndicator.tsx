import { Wifi } from "lucide-react";
import type { Tool } from "../app/tools";
import { useNetwork } from "../app/network";

/* =========================
   Network Indicator
   ========================= */

/* The words shown on hover, and read out by screen readers. */
const LABELS: Record<NonNullable<Tool["network"]>, string> = {
  required: "Requires network access",
  optional: "Optional network access",
};

/* A small, muted icon that marks a tool as using the network. It is the same everywhere a tool is */
/* listed, so any navigation can use it. It stays visible when network access is off, only quieter. */
export default function NetworkIndicator({ level }: { level: Tool["network"] }) {
  const { enabled } = useNetwork();
  if (!level) return null;

  return (
    <span
      className="network-indicator"
      data-on={enabled ? "true" : undefined}
      role="img"
      aria-label={LABELS[level]}
      title={LABELS[level]}
    >
      <Wifi size={14} strokeWidth={1.75} aria-hidden="true" />
    </span>
  );
}
