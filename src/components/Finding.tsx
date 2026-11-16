import { Fragment } from "react";

/* =========================
   Finding
   ========================= */

/* Every tool reports results in this shape. There is no score. */
export type FindingStatus = "ok" | "info" | "warning" | "risk";

export interface Finding {
  id: string;
  status: FindingStatus;
  title: string;
  detected: string;
  why: string;
  action?: string;
  details?: { label: string; value: string }[];
}

/* The label carries the meaning so colour is never the only signal. */
const STATUS_LABELS: Record<FindingStatus, string> = {
  ok: "No issue found",
  info: "Note",
  warning: "Needs attention",
  risk: "Action recommended",
};

export default function FindingCard({ finding }: { finding: Finding }) {
  return (
    <article className="finding" data-status={finding.status}>
      <header className="finding-header">
        <span className="finding-status">{STATUS_LABELS[finding.status]}</span>
        <h3>{finding.title}</h3>
      </header>

      <dl className="finding-body">
        <dt>Detected</dt>
        <dd>{finding.detected}</dd>
        <dt>Why it matters</dt>
        <dd>{finding.why}</dd>
        {finding.action && (
          <>
            <dt>Recommended</dt>
            <dd>{finding.action}</dd>
          </>
        )}
      </dl>

      {finding.details && (
        <details>
          <summary>Technical details</summary>
          <dl className="details-list">
            {finding.details.map((detail) => (
              <Fragment key={detail.label}>
                <dt>{detail.label}</dt>
                <dd>{detail.value}</dd>
              </Fragment>
            ))}
          </dl>
        </details>
      )}
    </article>
  );
}
