import type { FindingStatus } from "./Finding";

/* =========================
   Verdict
   ========================= */

/* The overall result of a tool, worked out in Rust. It must match the Verdict struct in finding.rs. */
/* A limited analysis is its own result, because it is not a clean one. */
export interface Verdict {
  status: FindingStatus;
  headline: string;
  detail: string;
}

/* The headline result and one line under it. It is announced to screen readers when it appears. */
export default function VerdictBlock({ verdict }: { verdict: Verdict }) {
  return (
    <div role="status">
      <p className="verdict" data-status={verdict.status}>
        {verdict.headline}
      </p>
      <p className="verdict-detail">{verdict.detail}</p>
    </div>
  );
}
