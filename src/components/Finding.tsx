import CopyButton from "./CopyButton";
import { BadgeInfo, CircleAlert, CircleCheck, CircleHelp, Info, TriangleAlert, type LucideIcon } from "lucide-react";

/* =========================
   Finding
   ========================= */

/* Every tool reports results in this shape. There is no score. */
/* It must match the Finding struct in src-tauri/src/finding.rs. */
/* "limited" means the check ran but information it needed was missing, so it cannot say either way. */
export type FindingStatus = "ok" | "info" | "limited" | "warning" | "risk" | "unknown";

export interface FindingDetail {
  label: string;
  value: string;
  /* Set for things that are either on or off. */
  active?: boolean;
  /* Why this item matters. It is folded away until the reader asks for it. */
  reason?: string;
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

/* A web address a check found, with a short assessment. It is shown as text, never as a link. */
export interface FindingUrl {
  url: string;
  status: FindingStatus;
  assessment: string;
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
  /* Web addresses the check found, each with its own assessment. */
  urls?: FindingUrl[];
  /* Left out by simulated results, which did not run anything. */
  steps?: Step[];
}

/* Each status has its own icon shape and label, so colour is never the only signal. */
const STATUSES: Record<FindingStatus, { label: string; icon: LucideIcon }> = {
  ok: { label: "No issue found", icon: CircleCheck },
  info: { label: "Note", icon: Info },
  limited: { label: "Limited analysis", icon: BadgeInfo },
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

interface FindingCardProps {
  finding: Finding;
  link?: FindingLink;
  /* Sends an address to the URL Checker. The button only appears when this is given. */
  onAnalyseUrl?: (url: string) => void;
}

export default function FindingCard({ finding, link, onAnalyseUrl }: FindingCardProps) {
  const status = STATUSES[finding.status];
  const reasons = (finding.details ?? []).filter((detail) => detail.reason);

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

      {finding.urls && finding.urls.length > 0 && (
        <ul className="finding-urls" aria-label="Links in this email">
          {finding.urls.map((item, index) => {
            const itemStatus = STATUSES[item.status];
            return (
              <li key={`${item.url}-${index}`} data-status={item.status}>
                <itemStatus.icon className="finding-icon" size={16} strokeWidth={1.75} role="img" aria-label={itemStatus.label} />
                <div className="finding-url-text">
                  {/* Plain text, so a suspicious address cannot be opened by accident. */}
                  <code>{item.url}</code>
                  <span>{item.assessment}</span>
                </div>
                <div className="finding-url-actions">
                  <CopyButton text={item.url} ariaLabel={`Copy link ${index + 1}`} />
                  {onAnalyseUrl && (
                    <button type="button" className="button button-small" onClick={() => onAnalyseUrl(item.url)}>
                      Analyse in URL Checker
                    </button>
                  )}
                </div>
              </li>
            );
          })}
        </ul>
      )}

      {reasons.length > 0 && (
        <details className="finding-why">
          <summary>Why this matters</summary>
          <ul>
            {reasons.map((detail, index) => (
              <li key={`${detail.label}-${index}`}>
                <strong>{detail.label}</strong> {detail.reason}
              </li>
            ))}
          </ul>
        </details>
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
