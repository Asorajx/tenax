import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { Tool } from "../app/tools";
import ActivityLog from "../components/ActivityLog";
import FindingCard, { type Finding, type FindingStatus } from "../components/Finding";
import ToolPage from "../components/ToolPage";

/* =========================
   Email Headers
   ========================= */

/* The most that can be pasted. Headers are far shorter than this. */
const MAX_LENGTH = 200000;

/* What the verdict says for each result. It never claims an email is safe. */
const VERDICTS: Partial<Record<FindingStatus, string>> = {
  risk: "The sender of this email could not be verified.",
  warning: "Some details of this email need a closer look.",
  info: "These headers do not give enough to verify the sender.",
  ok: "No obvious issues detected in these headers.",
};

type CheckState = "idle" | "loading" | "done" | "error";

export default function EmailHeaders({ tool }: { tool: Tool }) {
  const [headers, setHeaders] = useState("");
  const [state, setState] = useState<CheckState>("idle");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [seconds, setSeconds] = useState(0);
  const [error, setError] = useState("");
  /* After a successful analysis the pasted text is folded away until Edit is pressed. */
  const [editing, setEditing] = useState(false);

  /* Results belong to the headers that were analysed, so changing them clears the results. */
  function changeHeaders(next: string) {
    setHeaders(next);
    if (state === "done" || state === "error") setState("idle");
  }

  /* Asks the Rust backend to read the headers, then shows what it finds. */
  async function runCheck() {
    if (!headers.trim() || state === "loading") return;
    setState("loading");
    const started = performance.now();
    try {
      setFindings(await invoke<Finding[]>("analyse_email_headers", { raw: headers }));
      setSeconds((performance.now() - started) / 1000);
      setEditing(false);
      setState("done");
    } catch (reason) {
      setError(String(reason));
      setState("error");
    }
  }

  /* The delivery path is only background, and a note about the Return-Path should not outweigh */
  /* a pass. So the verdict is the worst real concern, or else what authentication found. */
  const checks = findings.filter((finding) => finding.id !== "path");
  const status =
    (["risk", "warning", "unknown"] as const).find((concern) => checks.some((finding) => finding.status === concern)) ??
    findings.find((finding) => finding.id === "authentication")?.status;

  const collapsed = state === "done" && !editing;
  const info = <p>{tool.privacy}</p>;

  return (
    <ToolPage tool={tool} info={info}>
      {collapsed ? (
        <div className="input-summary">
          <span>Email headers provided · {headers.split("\n").length} lines</span>
          <button type="button" className="button" onClick={() => setEditing(true)}>
            Edit
          </button>
        </div>
      ) : (
        <>
          <textarea
            className="text-area"
            value={headers}
            maxLength={MAX_LENGTH}
            placeholder="Paste the full email headers here"
            aria-label="Email headers"
            autoComplete="off"
            autoCapitalize="off"
            spellCheck={false}
            onChange={(event) => changeHeaders(event.target.value)}
          />
          <div className="field">
            <button
              type="button"
              className="button button-primary"
              disabled={!headers.trim() || state === "loading"}
              onClick={runCheck}
            >
              {state === "loading" ? "Analysing…" : "Analyse"}
            </button>
            {headers && (
              <button type="button" className="button" onClick={() => changeHeaders("")}>
                Clear
              </button>
            )}
          </div>
        </>
      )}

      {state === "error" && (
        <div className="notice" data-tone="error" role="alert">
          {error}
        </div>
      )}

      {state === "done" && (
        <>
          <p className="verdict" data-status={status} role="status">
            {status ? VERDICTS[status] : ""}
          </p>
          <div className="findings">
            {findings.map((finding) => (
              <FindingCard key={finding.id} finding={finding} />
            ))}
          </div>
          <ActivityLog
            title="Email Headers"
            findings={findings}
            seconds={seconds}
            footer="Analysed on this device · Headers not stored · No data transmitted"
          />
        </>
      )}
    </ToolPage>
  );
}
