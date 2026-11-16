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
  /* Text hidden when the log is copied, such as the hash prefix that was sent. */
  redact?: string;
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
  /* A short explanation under the details, such as what a result does and does not mean. */
  note?: string;
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

/* The action text, with the link phrase turned into a button when the text contains it. */
function withLink(action: string, link?: FindingLink) {
  const index = link ? action.indexOf(link.text) : -1;
  if (!link || index === -1) return action;
  return (
    <>
      {action.slice(0, index)}
      <button type="button" className="inline-link" onClick={link.onClick}>
        {link.text}
      </button>
      {action.slice(index + link.text.length)}
    </>
  );
}

/* One card per check. It shows the state, what is on and off, and what to do if anything. */
/* A phrase inside the "What to do" text that can be clicked, such as the name of another tool. */
export interface FindingLink {
  text: string;
  onClick: () => void;
}

export default function FindingCard({ finding, link }: { finding: Finding; link?: FindingLink }) {
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

      {finding.note && <p className="finding-note">{finding.note}</p>}

      {finding.action && (
        <p className="finding-action">
          <strong>What to do</strong>
          <span>{withLink(finding.action, link)}</span>
        </p>
      )}
    </article>
  );
}
