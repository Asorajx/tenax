import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { Tool } from "../app/tools";
import ActivityLog from "../components/ActivityLog";
import FindingCard, { type Finding } from "../components/Finding";
import ToolPage from "../components/ToolPage";

/* =========================
   Windows Security
   ========================= */

/* The checks this page runs, shown before the first run. */
const CHECKS = ["Antivirus", "Firewall", "Windows Update"];

/* How long the icon takes to finish filling once the results are in. */
const FILL_FINISH_MS = 180;

/* "finishing" is the brief moment between the results arriving and being shown. */
type CheckState = "idle" | "loading" | "finishing" | "done" | "error";

export default function WindowsSecurity({ tool }: { tool: Tool }) {
  const [state, setState] = useState<CheckState>("idle");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [seconds, setSeconds] = useState(0);
  const [error, setError] = useState("");

  /* Asks the Rust backend to read the settings, then shows what it returns. */
  async function runCheck() {
    setState("loading");
    const started = performance.now();
    try {
      setFindings(await invoke<Finding[]>("check_windows_security"));
      setSeconds((performance.now() - started) / 1000);

      /* The results are in, so the icon fills the rest of the way before they are shown. */
      setState("finishing");
      window.setTimeout(() => setState("done"), FILL_FINISH_MS);
    } catch (reason) {
      setError(String(reason));
      setState("error");
    }
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
      <p>Correct settings lower risk, but they cannot confirm a PC is secure.</p>
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
            <p>It takes about a second, and nothing is changed.</p>
          </div>
          <button
            type="button"
            className="button button-primary button-large"
            disabled={state !== "idle"}
            onClick={runCheck}
          >
            Run check
          </button>
          <ul className="hero-checks" aria-label="What is checked">
            {CHECKS.map((check) => (
              <li key={check}>{check}</li>
            ))}
          </ul>
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
            footer="Read-only · No settings changed · No data transmitted"
          />
        </>
      )}
    </ToolPage>
  );
}
