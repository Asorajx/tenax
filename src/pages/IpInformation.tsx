import { useRef, useState, type ReactNode } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { Tool } from "../app/tools";
import ActivityLog from "../components/ActivityLog";
import FindingCard, { type Finding } from "../components/Finding";
import ToolPage from "../components/ToolPage";
import VerdictBlock, { type Verdict } from "../components/VerdictBlock";

/* =========================
   IP Information
   ========================= */

/* The most that can be typed. It must match MAX_INPUT in src-tauri/src/ip_info/address.rs. */
const MAX_LENGTH = 2048;

/* The outside service that receives the address, named wherever the user is asked. */
const SERVICE = "ipinfo.io";

interface IpReport {
  /* The address as Tenax read it. The optional lookups use this, not the typed text. */
  address: string;
  verdict: Verdict;
  findings: Finding[];
  canReverse: boolean;
  canExternal: boolean;
}

type CheckState = "idle" | "loading" | "done" | "error";
type LookupState = "idle" | "loading" | "done";

/* One optional lookup: nothing yet, running, or a finished card. A failed lookup is a card too. */
interface Lookup {
  state: LookupState;
  finding: Finding | null;
}

const NOT_ASKED: Lookup = { state: "idle", finding: null };

/* A section of the results, labelled with where its information came from. */
function Source({
  title,
  tag,
  external,
  children,
}: {
  title: string;
  tag: string;
  external?: boolean;
  children: ReactNode;
}) {
  return (
    <section className="source">
      <div className="source-head">
        <h2>{title}</h2>
        <span className="source-tag" data-external={external ? "true" : undefined}>
          {tag}
        </span>
      </div>
      {children}
    </section>
  );
}

/* Only the address type is worked out when Inspect is pressed, and it is worked out on this PC. */
/* The other two lookups send the address somewhere, so each has its own button. The one that */
/* goes to an outside service asks for a second, explicit click that names the service. */
export default function IpInformation({ tool }: { tool: Tool }) {
  const [address, setAddress] = useState("");
  const [state, setState] = useState<CheckState>("idle");
  const [report, setReport] = useState<IpReport | null>(null);
  const [seconds, setSeconds] = useState(0);
  const [error, setError] = useState("");

  const [reverse, setReverse] = useState<Lookup>(NOT_ASKED);
  const [owner, setOwner] = useState<Lookup>(NOT_ASKED);
  const [confirming, setConfirming] = useState(false);

  /* Only the newest address may show results, so an answer for an old one is thrown away. */
  const latest = useRef(0);

  /* Results belong to the address that was inspected, so changing it clears all of them. */
  function changeAddress(next: string) {
    setAddress(next);
    latest.current++;
    if (state !== "idle") setState("idle");
    setReverse(NOT_ASKED);
    setOwner(NOT_ASKED);
    setConfirming(false);
  }

  /* Reads the address on this PC. Nothing is sent anywhere. */
  async function inspect() {
    if (!address.trim() || state === "loading") return;
    const mine = ++latest.current;
    setReverse(NOT_ASKED);
    setOwner(NOT_ASKED);
    setConfirming(false);
    setState("loading");
    const started = performance.now();
    try {
      const result = await invoke<IpReport>("inspect_ip", { address });
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

  /* Runs one optional lookup for the address Tenax read, and keeps its card. */
  async function runLookup(command: string, set: (lookup: Lookup) => void) {
    if (!report) return;
    const mine = latest.current;
    set({ state: "loading", finding: null });
    try {
      const finding = await invoke<Finding>(command, { address: report.address });
      if (mine !== latest.current) return;
      set({ state: "done", finding });
    } catch (reason) {
      if (mine !== latest.current) return;
      set(NOT_ASKED);
      setError(String(reason));
      setState("error");
    }
  }

  function askOwner() {
    setConfirming(false);
    runLookup("lookup_ip_owner", setOwner);
  }

  /* The log lists only what was actually done, and says what was sent and where. */
  const sent = ["Address type worked out on this PC"];
  if (reverse.finding) sent.push("address sent to this PC's DNS server");
  if (owner.finding) sent.push(`address sent to ${SERVICE}`);
  const footer = reverse.finding || owner.finding ? sent.join(" · ") : `${sent[0]} · Nothing was sent`;

  const logged = [...(report?.findings ?? []), ...[reverse.finding, owner.finding].filter((f): f is Finding => !!f)];

  return (
    <ToolPage tool={tool} info={<p>{tool.privacy}</p>}>
      <p className="network-note">
        The address type is worked out on this PC. Nothing is sent anywhere unless you choose a lookup below.
      </p>

      <form
        className="field"
        onSubmit={(event) => {
          event.preventDefault();
          inspect();
        }}
      >
        <input
          type="text"
          value={address}
          maxLength={MAX_LENGTH}
          placeholder="Enter an IP address, such as 8.8.8.8 or 2001:4860:4860::8888"
          aria-label="IP address to inspect"
          autoComplete="off"
          autoCapitalize="off"
          spellCheck={false}
          onChange={(event) => changeAddress(event.target.value)}
        />
        {address && (
          <button type="button" className="button" onClick={() => changeAddress("")}>
            Clear
          </button>
        )}
        <button type="submit" className="button button-primary" disabled={!address.trim() || state === "loading"}>
          {state === "loading" ? "Inspecting…" : "Inspect"}
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

          <Source title="Address type" tag="On this PC">
            <div className="findings">
              {report.findings.map((finding) => (
                <FindingCard key={finding.id} finding={finding} />
              ))}
            </div>
          </Source>

          <Source title="Reverse DNS" tag="This PC's DNS server">
            {reverse.finding ? (
              <div className="findings">
                <FindingCard finding={reverse.finding} />
              </div>
            ) : (
              <div className="source-ask">
                <p>
                  {report.canReverse
                    ? "Asks the DNS server this PC already uses which name this address has. The address is sent to that server, which may pass the question on."
                    : "Not offered for this kind of address, because it has no name worth asking for."}
                </p>
                {report.canReverse && (
                  <button
                    type="button"
                    className="button"
                    disabled={reverse.state === "loading"}
                    onClick={() => runLookup("reverse_dns", setReverse)}
                  >
                    {reverse.state === "loading" ? "Looking up…" : "Look up name"}
                  </button>
                )}
              </div>
            )}
          </Source>

          <Source title="Owner and location" tag={`External · ${SERVICE}`} external>
            {owner.finding ? (
              <div className="findings">
                <FindingCard finding={owner.finding} />
              </div>
            ) : confirming ? (
              <div className="notice" role="alertdialog" aria-label={`Send the address to ${SERVICE}?`}>
                <p className="source-warning">
                  <strong>
                    This sends {report.address} to {SERVICE}, an outside service run by IPinfo.
                  </strong>{" "}
                  It will also see your PC's own internet address, as any website does, and may keep a record of the
                  request. Nothing else is sent.
                </p>
                <div className="source-actions">
                  <button type="button" className="button button-primary" onClick={askOwner}>
                    Send to {SERVICE}
                  </button>
                  <button type="button" className="button" onClick={() => setConfirming(false)}>
                    Cancel
                  </button>
                </div>
              </div>
            ) : (
              <div className="source-ask">
                <p>
                  {report.canExternal
                    ? `Asks ${SERVICE}, an outside service, who runs this network and roughly where it is. It only runs if you confirm.`
                    : "Not offered for this address, because only public addresses can be looked up with an outside service."}
                </p>
                {report.canExternal && (
                  <button
                    type="button"
                    className="button"
                    disabled={owner.state === "loading"}
                    onClick={() => setConfirming(true)}
                  >
                    {owner.state === "loading" ? "Looking up…" : "Look up owner…"}
                  </button>
                )}
              </div>
            )}
          </Source>

          <ActivityLog
            title="IP Information"
            findings={logged}
            seconds={seconds}
            result={report.verdict.headline}
            footer={footer}
          />
        </>
      )}
    </ToolPage>
  );
}
