import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { Tool } from "../app/tools";
import ActivityLog from "../components/ActivityLog";
import FindingCard, { type Finding } from "../components/Finding";
import ToolPage from "../components/ToolPage";
import VerdictBlock, { type Verdict } from "../components/VerdictBlock";

/* =========================
   URL Checker
   ========================= */

/* The most that can be typed. It must match MAX_LENGTH in src-tauri/src/url_check/mod.rs. */
const MAX_LENGTH = 4096;

interface UrlReport {
  verdict: Verdict;
  findings: Finding[];
}

interface UrlCheckerProps {
  tool: Tool;
  /* An address sent from another tool. It is entered and checked at once. The check only reads */
  /* how the address is written, so nothing is opened or sent anywhere. */
  handoff: { value: string } | null;
  onHandoffUsed: () => void;
}

type CheckState = "idle" | "loading" | "done" | "error";

export default function UrlChecker({ tool, handoff, onHandoffUsed }: UrlCheckerProps) {
  const [url, setUrl] = useState("");
  const [state, setState] = useState<CheckState>("idle");
  const [report, setReport] = useState<UrlReport | null>(null);
  const [seconds, setSeconds] = useState(0);
  const [error, setError] = useState("");

  /* Only the newest check may show its result, in case two are started close together. */
  const latest = useRef(0);

  /* Asks the Rust backend to read the address, then shows what it finds. Nothing is opened. */
  async function check(address: string) {
    const mine = ++latest.current;
    setState("loading");
    const started = performance.now();
    try {
      const result = await invoke<UrlReport>("check_url", { url: address });
      if (mine !== latest.current) return;
      setReport(result);
      setSeconds((performance.now() - started) / 1000);
      setState("done");
    } catch (reason) {
      if (mine !== latest.current) return;
      setError(String(reason));
      setState("error");
    }
  }

  /* An address sent from another tool is entered and checked at once. Only addresses sent this */
  /* way run without Check being pressed, and the same handoff is never handled twice. */
  /* Only the local check may run from here. A lookup that sends the address to a third party */
  /* must never start from a handoff. It needs its own button, with a clear warning. */
  const handled = useRef<object | null>(null);
  useEffect(() => {
    if (!handoff || handled.current === handoff) return;
    handled.current = handoff;
    setUrl(handoff.value);
    check(handoff.value);
    onHandoffUsed();
  }, [handoff, onHandoffUsed]);

  /* Results belong to the address that was checked, so changing it clears them. */
  function changeUrl(next: string) {
    setUrl(next);
    if (state === "done" || state === "error") setState("idle");
  }

  /* Pressing Check, or Enter, checks what is in the box. */
  function runCheck() {
    if (!url.trim() || state === "loading") return;
    check(url);
  }

  return (
    <ToolPage tool={tool} info={<p>{tool.privacy}</p>}>
      <form
        className="field"
        onSubmit={(event) => {
          event.preventDefault();
          runCheck();
        }}
      >
        <input
          type="text"
          inputMode="url"
          value={url}
          maxLength={MAX_LENGTH}
          placeholder="Paste a web address, such as https://example.com/login"
          aria-label="Web address to check"
          autoComplete="off"
          autoCapitalize="off"
          spellCheck={false}
          onChange={(event) => changeUrl(event.target.value)}
        />
        {url && (
          <button type="button" className="button" onClick={() => changeUrl("")}>
            Clear
          </button>
        )}
        <button type="submit" className="button button-primary" disabled={!url.trim() || state === "loading"}>
          {state === "loading" ? "Checking…" : "Check"}
        </button>
      </form>

      {state === "error" && (
        <div className="notice" data-tone="error" role="alert">
          {error}
        </div>
      )}

      {state === "done" && report && (
        <>
          <VerdictBlock verdict={report.verdict} />
          <div className="findings">
            {report.findings.map((finding) => (
              <FindingCard key={finding.id} finding={finding} />
            ))}
          </div>
          <ActivityLog
            title="URL Checker"
            findings={report.findings}
            seconds={seconds}
            result={report.verdict.headline}
            footer="Analysed on this device · Address not opened or stored · No data transmitted"
          />
        </>
      )}
    </ToolPage>
  );
}
