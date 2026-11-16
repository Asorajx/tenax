import { CircleAlert, CircleCheck, CircleHelp, Info, TriangleAlert, type LucideIcon } from "lucide-react";

/* =========================
   Finding
   ========================= */

/* Every tool reports results in this shape. There is no score. */
/* It must match the Finding struct in src-tauri/src/finding.rs. */
export type FindingStatus = "ok" | "info" | "warning" | "risk" | "unknown";

export interface FindingDetail {
  label: string;
  value: string;
  /* Set for things that are either on or off. */
  active?: boolean;
}

/* One thing Tenax did while running a check. It must match the Step struct in finding.rs. */
export interface Step {
  action: string;
  plain: string;
  method: string;
  ok: boolean;
  result: string;
  ms: number;
}

export interface Finding {
  id: string;
  status: FindingStatus;
  title: string;
  summary: string;
  checked: string;
  why: string;
  action?: string;
  details?: FindingDetail[];
  /* Left out by simulated results, which did not run anything. */
  steps?: Step[];
}

/* Each status has its own icon shape and label, so colour is never the only signal. */
const STATUSES: Record<FindingStatus, { label: string; icon: LucideIcon }> = {
  ok: { label: "No issue found", icon: CircleCheck },
  info: { label: "Note", icon: Info },
  warning: { label: "Needs attention", icon: TriangleAlert },
  risk: { label: "Action recommended", icon: CircleAlert },
  unknown: { label: "Could not check", icon: CircleHelp },
};

/* One card per check. It shows the state, what is on and off, and what to do if anything. */
export default function FindingCard({ finding }: { finding: Finding }) {
  const status = STATUSES[finding.status];

  return (
    <article className="finding" data-status={finding.status}>
      <header className="finding-header">
        <status.icon className="finding-icon" size={18} strokeWidth={1.75} role="img" aria-label={status.label} />
        <h3>{finding.title}</h3>
        <span className="finding-state">{finding.summary}</span>
      </header>

      {finding.details && (
        <ul className="finding-items">
          {finding.details.map((detail, index) => (
            <li key={`${detail.label}-${index}`}>
              <span className="finding-dot" data-active={detail.active} aria-hidden="true" />
              <span>{detail.label}</span>
              <span className="finding-value">{detail.value}</span>
            </li>
          ))}
        </ul>
      )}

      {finding.action && (
        <p className="finding-action">
          <strong>What to do</strong>
          {finding.action}
        </p>
      )}
    </article>
  );
}
