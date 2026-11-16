import { useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { Tool } from "../app/tools";
import ActivityLog from "../components/ActivityLog";
import FindingCard, { type Finding } from "../components/Finding";
import ToolPage from "../components/ToolPage";
import VerdictBlock, { type Verdict } from "../components/VerdictBlock";

/* =========================
   DNS Lookup
   ========================= */

/* The most that can be typed. It must match MAX_INPUT in src-tauri/src/dns_lookup/mod.rs. */
const MAX_LENGTH = 2048;

interface DnsReport {
  verdict: Verdict;
  findings: Finding[];
}

type CheckState = "idle" | "loading" | "done" | "error";

/* A lookup only ever runs when Look up is pressed. Nothing else starts one, and no other tool */
/* hands an address to this page, because a lookup sends the domain name over the network. */
export default function DnsLookup({ tool }: { tool: Tool }) {
  const [domain, setDomain] = useState("");
  const [state, setState] = useState<CheckState>("idle");
  const [report, setReport] = useState<DnsReport | null>(null);
  const [seconds, setSeconds] = useState(0);
  const [error, setError] = useState("");

  /* The privacy notice is shown until the first lookup has been asked for. */
  const [noticeSeen, setNoticeSeen] = useState(false);

  /* Only the newest lookup may show its result, in case two are started close together. */
  const latest = useRef(0);

  /* Results belong to the name that was looked up, so changing it clears them. If a lookup is */
  /* still waiting for its answer, that answer is thrown away, so it is never shown beside a */
  /* different name. */
  function changeDomain(next: string) {
    setDomain(next);
    if (state === "loading") latest.current++;
    if (state !== "idle") setState("idle");
  }

  /* Asks the Rust backend to look the name up with this PC's DNS server. */
  async function lookUp() {
    if (!domain.trim() || state === "loading") return;
    const mine = ++latest.current;
    setNoticeSeen(true);
    setState("loading");
    const started = performance.now();
    try {
      const result = await invoke<DnsReport>("lookup_dns", { domain });
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
          Uses the network: the domain name is sent to this PC's DNS server. Tenax's other checks run offline.
        </p>
      ) : (
        <div className="notice" role="note">
          <strong>This lookup uses the network.</strong> Tenax will send the domain name to the DNS server this PC
          already uses, the same one your browser uses. That server may pass the question on to others, as it does for
          any website you visit. Nothing else is sent, and Tenax's other checks run offline.
        </div>
      )}

      <form
        className="field"
        onSubmit={(event) => {
          event.preventDefault();
          lookUp();
        }}
      >
        <input
          type="text"
          value={domain}
          maxLength={MAX_LENGTH}
          placeholder="Enter a domain name, such as example.com"
          aria-label="Domain name to look up"
          autoComplete="off"
          autoCapitalize="off"
          spellCheck={false}
          onChange={(event) => changeDomain(event.target.value)}
        />
        {domain && (
          <button type="button" className="button" onClick={() => changeDomain("")}>
            Clear
          </button>
        )}
        <button type="submit" className="button button-primary" disabled={!domain.trim() || state === "loading"}>
          {state === "loading" ? "Looking up…" : "Look up"}
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
            title="DNS Lookup"
            findings={report.findings}
            seconds={seconds}
            result={report.verdict.headline}
            footer="Asked this PC's DNS server about the domain · Only the domain name was sent"
          />
        </>
      )}
    </ToolPage>
  );
}
