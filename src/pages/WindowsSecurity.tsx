import { useState } from "react";
import { useDeviceCheck } from "../app/deviceCheck";
import type { Tool } from "../app/tools";
import ActivityLog from "../components/ActivityLog";
import FindingCard from "../components/Finding";
import ToolPage from "../components/ToolPage";

/* =========================
   Windows Security
   ========================= */

/* How long the icon takes to finish filling once the results are in. */
const FILL_FINISH_MS = 180;

/* "finishing" is the brief moment between the results arriving and being shown. */
type CheckState = "idle" | "loading" | "finishing" | "done" | "error";

export default function WindowsSecurity({ tool }: { tool: Tool }) {
  /* The result is shared with the Home screen, so it is read once and shown in both. If it was already */
  /* read there, this page opens straight onto it. */
  const { phase, findings, seconds, error, run } = useDeviceCheck();
  const [finishing, setFinishing] = useState(false);
  const state: CheckState = phase === "done" && finishing ? "finishing" : phase;

  /* Reads the settings, then lets the icon fill the rest of the way before the results are shown. */
  async function runCheck() {
    setFinishing(true);
    await run();
    window.setTimeout(() => setFinishing(false), FILL_FINISH_MS);
  }

  /* The one-line result shown above the findings. It only speaks for the checks that ran. */
  const issues = findings.filter((finding) => finding.status === "risk" || finding.status === "warning");
  const failed = findings.filter((finding) => finding.status === "unknown");
  let verdict = { status: "ok", text: "No issues found." };
  if (issues.length > 0) {
    verdict = {
      status: issues.some((finding) => finding.status === "risk") ? "risk" : "warning",
      text: issues.length === 1 ? "1 issue needs attention." : `${issues.length} issues need attention.`,
    };
  } else if (failed.length > 0) {
    verdict = {
      status: "unknown",
      text: failed.length === 1 ? "1 check could not run." : `${failed.length} checks could not run.`,
    };
  }

  const info = (
    <>
      <p>Tenax only reads these settings. Nothing is changed, and nothing leaves this PC.</p>
    </>
  );

  /* Once there are results, the button steps back so the findings are the focus. */
  const runAgain = (state === "done" || state === "error") && (
    <button type="button" className="button button-primary" onClick={runCheck}>
      Run again
    </button>
  );

  return (
    <ToolPage tool={tool} info={info} action={runAgain}>
      {/* Ready and checking share one layout, so the icon stays put while it fills. */}
      {(state === "idle" || state === "loading" || state === "finishing") && (
        <div className="hero" data-phase={state}>
          <div className="hero-icon">
            <tool.icon size={28} strokeWidth={1.5} aria-hidden="true" />
            <tool.icon className="hero-icon-fill" size={28} strokeWidth={1.5} aria-hidden="true" />
          </div>
          <div className="hero-text" role="status">
            <h2>{state === "idle" ? "Ready to check this PC" : "Reading Windows security settings…"}</h2>
          </div>
          <button
            type="button"
            className="button button-primary button-large"
            disabled={state !== "idle"}
            onClick={runCheck}
          >
            Run check
          </button>
        </div>
      )}

      {state === "error" && (
        <div className="notice" data-tone="error" role="alert">
          The check could not run, so there are no findings to show. {error}
        </div>
      )}

      {state === "done" && (
        <>
          <p className="verdict" data-status={verdict.status}>
            {verdict.text}
          </p>
          <div className="findings">
            {findings.map((finding) => (
              <FindingCard key={finding.id} finding={finding} />
            ))}
          </div>
          <ActivityLog
            title="Windows Security"
            findings={findings}
            seconds={seconds}
            footer="Read-only check · No settings changed"
          />
        </>
      )}
    </ToolPage>
  );
}
