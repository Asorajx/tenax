import { useEffect, useRef, useState } from "react";
import { ScanSearch } from "lucide-react";
import { useDeviceCheck } from "../app/deviceCheck";
import { ALL_TOOLS } from "../app/tools";
import { useRecent } from "../app/recent";
import { WORKSPACES } from "../app/workspaces";
import DeviceRing, { deviceStatus, extraChecks, statusWord } from "../components/floating/DeviceRing";

/* =========================
   Home (Minimal)
   ========================= */

/* The least time, in milliseconds, the ring shows "Checking" before a result. */
const MIN_READ_MS = 700;

/* The landing screen for the floating layout. On the left is what Tenax is and the main action. On the */
/* right is a ring for the three Windows Security checks, which stays "Not checked" until someone asks. */
export default function HomeMinimal({
  onOpen,
  onOpenTool,
  onOpenFinding,
}: {
  onOpen: (workspace: string) => void;
  onOpenTool: (tool: string) => void;
  /* Opens Windows Security at one of its cards. */
  onOpenFinding: (finding: string) => void;
}) {
  const { results } = useRecent();
  const { phase: checkPhase, findings, checkedAt, error, run } = useDeviceCheck();

  /* A result that arrives at once still gets a short read, so the ring can finish its turn first. */
  const [phase, setPhase] = useState(checkPhase);
  const started = useRef(0);
  useEffect(() => {
    if (checkPhase === "loading") started.current = performance.now();
    const wait = checkPhase === "loading" ? 0 : Math.max(0, started.current + MIN_READ_MS - performance.now());
    const timer = window.setTimeout(() => setPhase(checkPhase), wait);
    return () => window.clearTimeout(timer);
  }, [checkPhase]);

  /* Only the two workspaces that are not shown above, as short ways in. */
  const more = WORKSPACES.filter((workspace) => workspace.id === "network" || workspace.id === "passwords");

  const time = checkedAt?.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

  /* The checks that have no segment on the ring, which the line in the middle also counts. */
  const extra = extraChecks(phase, findings);

  /* How many checks could not be read. It is shown quietly, apart from the headline. */
  const unavailable = phase === "done" ? deviceStatus(findings).unavailable : 0;

  return (
    <div className="home">
      <section className="home-top">
        <div className="home-intro">
          <h1>Tenax</h1>
          <div className="home-start">
            <button type="button" className="button button-primary button-large" onClick={() => onOpen("investigate")}>
              <ScanSearch size={16} strokeWidth={1.75} aria-hidden="true" />
              Start an investigation
            </button>
          </div>
          <div className="home-more">
            {more.map((workspace) => (
              <button key={workspace.id} type="button" onClick={() => onOpen(workspace.id)}>
                <workspace.icon size={16} strokeWidth={1.75} aria-hidden="true" />
                <span>
                  <span className="home-more-name">{workspace.label}</span>
                  <span>{workspace.summary}</span>
                </span>
              </button>
            ))}
          </div>
        </div>

        <div className="home-device">
          <div className="home-ring">
            <DeviceRing phase={phase} findings={findings} />
            <button type="button" className="button button-small" onClick={run} disabled={phase === "loading"}>
              {phase === "loading" ? "Checking…" : phase === "idle" ? "Check this PC" : "Check again"}
            </button>
          </div>
          {extra.length > 0 && (
            <ul className="home-checks" aria-label="Other Windows Security checks">
              {extra.map((check) => (
                <li key={check.id}>
                  <button
                    type="button"
                    onClick={() => onOpenFinding(check.id)}
                    aria-label={`${check.title}, ${check.summary}, ${statusWord(check.status)}`}
                  >
                    <span className="home-check-dot" data-status={check.status} aria-hidden="true" />
                    <span className="home-check-name">{check.title}</span>
                    <span className="home-check-state">{check.summary}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
          {/* Always present, so the page does not shift while a check runs. */}
          <p
            className="home-device-note"
            role={phase === "error" ? "alert" : undefined}
            data-hidden={!checkedAt && phase !== "error" ? "true" : undefined}
          >
            {phase === "error" ? (
              error
            ) : (
              <>
                Checked at {time} ·{" "}
                {unavailable > 0 && <>{unavailable} unavailable ·{" "}</>}
                <button type="button" className="button-link" onClick={() => onOpen("device")}>
                  Details
                </button>
              </>
            )}
          </p>
          <section className="home-recent" aria-labelledby="recent-heading">
            <h2 id="recent-heading">Recent</h2>
            {results.length === 0 ? (
              <p className="home-recent-empty">Nothing yet</p>
            ) : (
              <ul>
                {results.map((result) => (
                  <li key={result.title}>
                    <button
                      type="button"
                      onClick={() => onOpenTool(ALL_TOOLS.find((tool) => tool.label === result.title)?.id ?? "home")}
                    >
                      <span className="home-check-dot" data-status={result.status} aria-hidden="true" />
                      <span className="home-recent-name">{result.title}</span>
                      <time dateTime={result.at.toISOString()}>
                        {result.at.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                      </time>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>
      </section>
    </div>
  );
}
