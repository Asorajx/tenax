import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { Tool } from "../app/tools";
import ActivityLog from "../components/ActivityLog";
import FindingCard, { type Finding, type FindingStatus } from "../components/Finding";
import PasteBox from "../components/PasteBox";
import ToolPage from "../components/ToolPage";

/* =========================
   Email Scam Checker
   ========================= */

/* The overall result, worked out in Rust. It must match the Verdict struct in findings.rs. */
/* A limited analysis is its own result, because it is not a clean one. */
interface Verdict {
  status: FindingStatus;
  headline: string;
  detail: string;
}

interface ScamReport {
  verdict: Verdict;
  findings: Finding[];
}

type CheckState = "idle" | "loading" | "done" | "error";

interface EmailScamProps {
  tool: Tool;
  /* Sends a link to the URL Checker. It is only given when the URL Checker is ready. */
  onAnalyseUrl?: (url: string) => void;
}

export default function EmailScam({ tool, onAnalyseUrl }: EmailScamProps) {
  const [email, setEmail] = useState("");
  const [state, setState] = useState<CheckState>("idle");
  const [report, setReport] = useState<ScamReport | null>(null);
  const [seconds, setSeconds] = useState(0);
  const [error, setError] = useState("");

  /* Results belong to the text that was checked, so changing it clears them. */
  function changeEmail(next: string) {
    setEmail(next);
    if (state === "done" || state === "error") setState("idle");
  }

  /* Asks the Rust backend to read the email, then shows what it finds. */
  async function runCheck() {
    if (!email.trim() || state === "loading") return;
    setState("loading");
    const started = performance.now();
    try {
      setReport(await invoke<ScamReport>("check_email_scam", { raw: email }));
      setSeconds((performance.now() - started) / 1000);
      setState("done");
    } catch (reason) {
      setError(String(reason));
      setState("error");
    }
  }

  return (
    <ToolPage tool={tool} info={<p>{tool.privacy}</p>}>
      <PasteBox
        value={email}
        onChange={changeEmail}
        placeholder="Paste the email here. Pasting the full message source also lets Tenax check where links really go."
        ariaLabel="Email to check"
        summaryLabel="Email provided"
        loading={state === "loading"}
        done={state === "done"}
        onAnalyse={runCheck}
      />

      {state === "error" && (
        <div className="notice" data-tone="error" role="alert">
          {error}
        </div>
      )}

      {state === "done" && report && (
        <>
          <div role="status">
            <p className="verdict" data-status={report.verdict.status}>
              {report.verdict.headline}
            </p>
            <p className="verdict-detail">{report.verdict.detail}</p>
          </div>
          <div className="findings">
            {report.findings.map((finding) => (
              <FindingCard
                key={finding.id}
                finding={finding}
                onAnalyseUrl={finding.id === "links" ? onAnalyseUrl : undefined}
              />
            ))}
          </div>
          <ActivityLog
            title="Email Scam Checker"
            findings={report.findings}
            seconds={seconds}
            result={report.verdict.headline}
            footer="Analysed on this device · Email not stored · No data transmitted"
          />
        </>
      )}
    </ToolPage>
  );
}
