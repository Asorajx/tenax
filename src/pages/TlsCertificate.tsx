import { useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { Tool } from "../app/tools";
import ActivityLog from "../components/ActivityLog";
import FindingCard, { type Finding } from "../components/Finding";
import ToolPage from "../components/ToolPage";
import VerdictBlock, { type Verdict } from "../components/VerdictBlock";

/* =========================
   TLS Certificate
   ========================= */

/* The most that can be typed. It must match MAX_INPUT in src-tauri/src/tls_check/target.rs. */
const MAX_LENGTH = 2048;

interface TlsReport {
  verdict: Verdict;
  findings: Finding[];
}

type CheckState = "idle" | "loading" | "done" | "error";

/* A check only ever runs when Check is pressed. Nothing else starts one, and no other tool */
/* hands an address to this page, because a check connects to the server. */
export default function TlsCertificate({ tool }: { tool: Tool }) {
  const [host, setHost] = useState("");
  const [state, setState] = useState<CheckState>("idle");
  const [report, setReport] = useState<TlsReport | null>(null);
  const [seconds, setSeconds] = useState(0);
  const [error, setError] = useState("");

  /* The privacy notice is shown until the first check has been asked for. */
  const [noticeSeen, setNoticeSeen] = useState(false);

  /* Only the newest check may show its result, in case two are started close together. */
  const latest = useRef(0);

  /* Results belong to the host that was checked, so changing it clears them. If a check is */
  /* still waiting for its answer, that answer is thrown away, so it is never shown beside a */
  /* different host. */
  function changeHost(next: string) {
    setHost(next);
    if (state === "loading") latest.current++;
    if (state !== "idle") setState("idle");
  }

  /* Asks the Rust backend to connect and read the certificate. */
  async function checkCertificate() {
    if (!host.trim() || state === "loading") return;
    const mine = ++latest.current;
    setNoticeSeen(true);
    setState("loading");
    const started = performance.now();
    try {
      const result = await invoke<TlsReport>("check_tls", { host });
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

  return (
    <ToolPage tool={tool} info={<p>{tool.privacy}</p>}>
      {noticeSeen ? (
        <p className="network-note">
          Uses the network: Tenax connects to the server you enter. Only public hosts on port 443 are allowed.
        </p>
      ) : (
        <div className="notice" role="note">
          <strong>This check connects to the server you enter.</strong> Reading a certificate means starting a secure
          connection to that server, on port 443. Tenax only makes the handshake: it sends no web request, downloads
          nothing and follows no redirects. The server can see this PC's internet address, as any website can. No other
          service is contacted, and Tenax's other checks run offline.
        </div>
      )}

      <form
        className="field"
        onSubmit={(event) => {
          event.preventDefault();
          checkCertificate();
        }}
      >
        <input
          type="text"
          value={host}
          maxLength={MAX_LENGTH}
          placeholder="Enter a host name, such as example.com"
          aria-label="Host name to check"
          autoComplete="off"
          autoCapitalize="off"
          spellCheck={false}
          onChange={(event) => changeHost(event.target.value)}
        />
        {host && (
          <button type="button" className="button" onClick={() => changeHost("")}>
            Clear
          </button>
        )}
        <button type="submit" className="button button-primary" disabled={!host.trim() || state === "loading"}>
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
            title="TLS Certificate"
            findings={report.findings}
            seconds={seconds}
            result={report.verdict.headline}
            footer="Connected to the server you entered · Secure handshake only · No web request sent"
          />
        </>
      )}
    </ToolPage>
  );
}
