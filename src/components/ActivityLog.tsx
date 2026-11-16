import { useState, type MouseEvent } from "react";
import { Check, ChevronDown, Copy, SquareTerminal } from "lucide-react";
import type { Finding } from "./Finding";

/* =========================
   Activity Log
   ========================= */

interface ActivityLogProps {
  /* The tool's name, used in the copied log. */
  title: string;
  findings: Finding[];
  seconds: number;
  /* A closing line, such as what was not touched. */
  footer: string;
}

/* The chosen tab is remembered for future scans. Basic is the default. */
type Tab = "basic" | "advanced";
const TAB_KEY = "tenax-activity-tab";

function savedTab(): Tab {
  try {
    return localStorage.getItem(TAB_KEY) === "advanced" ? "advanced" : "basic";
  } catch {
    return "basic";
  }
}

/* Never shows 0.0s, because a check always takes some time. */
function formatSeconds(seconds: number) {
  return `${Math.max(seconds, 0.1).toFixed(1)}s`;
}

function formatMs(ms: number) {
  return ms < 1 ? "<1 ms" : `${Math.round(ms)} ms`;
}

/* The plain-text version of the log, for troubleshooting or sharing. */
function buildLog(title: string, findings: Finding[], seconds: number) {
  const lines = [`Tenax technical log: ${title}`, `Total time: ${formatSeconds(seconds)}`, ""];
  for (const step of findings.flatMap((finding) => finding.steps ?? [])) {
    lines.push(`[${step.ok ? "ok" : "failed"}] ${step.action} (${formatMs(step.ms)})`);
    lines.push(`    Method: ${step.method}`);
    lines.push(`    Result: ${step.result}`);
  }
  return lines.join("\n");
}

/* A collapsed terminal-style record of what Tenax did. Technical details open per step. */
export default function ActivityLog({ title, findings, seconds, footer }: ActivityLogProps) {
  const [copied, setCopied] = useState(false);
  const [tab, setTab] = useState<Tab>(savedTab);
  const hasSteps = findings.some((finding) => finding.steps?.length);

  /* The tabs sit in the header, so clicking one must not also open or close the terminal. */
  function chooseTab(event: MouseEvent, next: Tab) {
    event.preventDefault();
    /* A closed terminal would show no change, so choosing a tab also opens it. */
    event.currentTarget.closest("details")!.open = true;
    setTab(next);
    try {
      localStorage.setItem(TAB_KEY, next);
    } catch {
      /* Storage can be blocked, so the choice just is not remembered. */
    }
  }

  async function copyLog() {
    try {
      await navigator.clipboard.writeText(buildLog(title, findings, seconds));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      /* The clipboard can be blocked, so the button simply stays as it is. */
    }
  }

  return (
    <details className="terminal">
      <summary className="terminal-header">
        <SquareTerminal size={16} strokeWidth={1.75} aria-hidden="true" />
        <span>What Tenax did</span>
        <span className="terminal-tabs" data-tab={tab} role="tablist" aria-label="Level of detail">
          {(["basic", "advanced"] as const).map((name) => (
            <button
              key={name}
              type="button"
              role="tab"
              aria-selected={tab === name}
              className="terminal-tab"
              onClick={(event) => chooseTab(event, name)}
            >
              {name === "basic" ? "Basic" : "Advanced"}
            </button>
          ))}
        </span>
        <span className="terminal-meta">{formatSeconds(seconds)}</span>
        <ChevronDown className="terminal-chevron" size={16} aria-hidden="true" />
      </summary>

      <div className="terminal-body">
        {findings.map((finding) =>
          /* Simulated results have no steps, so they fall back to the check's own description. */
          /* A finding that needs no steps of its own, next to one that has them, is left out. */
          (finding.steps?.length ? finding.steps : hasSteps ? [] : [undefined]).map((step, index) => (
            <div key={`${tab}-${finding.id}-${index}`} className="terminal-entry">
              <p className="terminal-command">
                {tab === "basic" ? (step ? step.plain : finding.checked) : (step ? step.action : "No technical log: simulated result")}
              </p>
              {tab === "advanced" && step && (
                <>
                  <p>Method: {step.method}</p>
                  <p>
                    Status: {step.ok ? "Completed" : "Failed"} in {formatMs(step.ms)}
                  </p>
                  <p>Result: {step.result}</p>
                </>
              )}
            </div>
          )),
        )}

        <div className="terminal-footer">
          <span>{footer}</span>
          {hasSteps && (
            <button type="button" className="terminal-copy" onClick={copyLog}>
              {copied ? (
                <Check className="terminal-copied" size={14} aria-hidden="true" />
              ) : (
                <Copy size={14} aria-hidden="true" />
              )}
              {copied ? "Copied" : "Copy technical log"}
            </button>
          )}
        </div>
      </div>
    </details>
  );
}
