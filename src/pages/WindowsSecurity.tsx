import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useDeviceCheck } from "../app/deviceCheck";
import type { Tool } from "../app/tools";
import ActivityLog from "../components/ActivityLog";
import FindingCard, { type Finding, type FindingLink } from "../components/Finding";
import { deviceStatus } from "../components/floating/DeviceRing";
import ToolPage from "../components/ToolPage";

/* =========================
   Windows Security
   ========================= */

/* How long the icon takes to finish filling once the results are in. */
const FILL_FINISH_MS = 180;

/* The page of Windows Settings, or of the Windows Security app, that each check's "What to do" sends */
/* people to. It must match the pages in src-tauri/src/windows_security/settings.rs. */
const SETTINGS_PAGES: Record<string, string> = {
  antivirus: "virus-protection",
  firewall: "firewall",
  updates: "windows-update",
  startup: "device-security",
  uac: "settings",
  remote: "remote-desktop",
  encryption: "privacy",
};

/* When a card says "Open Settings" or "Open Windows Security", those words open that page. Opening */
/* it changes nothing, and a card whose text does not say it has no link. */
function settingsLink(finding: Finding): FindingLink | undefined {
  const page = SETTINGS_PAGES[finding.id];
  const text = ["Open Windows Security", "Open Settings"].find((phrase) => finding.action?.includes(phrase));
  if (!page || !text) return undefined;
  return {
    text,
    /* If the page cannot be opened, nothing happens, and the text still says where to go. */
    onClick: () => {
      invoke("open_settings", { page }).catch(() => {});
    },
  };
}

/* "finishing" is the brief moment between the results arriving and being shown. */
type CheckState = "idle" | "loading" | "finishing" | "done" | "error";

interface WindowsSecurityProps {
  tool: Tool;
  /* A card to scroll to, sent from the Home screen. */
  focus: string | null;
  onFocused: () => void;
}

export default function WindowsSecurity({ tool, focus, onFocused }: WindowsSecurityProps) {
  /* The result is shared with the Home screen, so it is read once and shown in both. If it was already */
  /* read there, this page opens straight onto it. */
  const { phase, findings, seconds, error, run } = useDeviceCheck();
  const [finishing, setFinishing] = useState(false);
  const state: CheckState = phase === "done" && finishing ? "finishing" : phase;

  /* Scrolls to the card the Home screen asked for, as soon as the results are showing. */
  const list = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!focus || state !== "done") return;
    /* Waits a frame, because the window returns a newly shown page to the top once it has rendered. */
    const frame = requestAnimationFrame(() => {
      const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      list.current?.querySelector(`[data-finding="${focus}"]`)?.scrollIntoView({ behavior: reduced ? "auto" : "smooth", block: "center" });
      onFocused();
    });
    return () => cancelAnimationFrame(frame);
  }, [focus, state, onFocused]);

  /* Reads the settings, then lets the icon fill the rest of the way before the results are shown. */
  async function runCheck() {
    setFinishing(true);
    await run();
    window.setTimeout(() => setFinishing(false), FILL_FINISH_MS);
  }

  /* The one-line result shown above the findings. It says the same as the Home screen, from the same */
  /* function: warnings first, then anything that could not be read. */
  const summary = deviceStatus(findings);
  const unread = summary.unavailable === 1 ? "1 check could not be fully read." : `${summary.unavailable} checks could not be fully read.`;
  let verdict: { status: string; text: string };
  if (summary.kind === "attention") {
    const issues = summary.attention === 1 ? "1 issue needs attention." : `${summary.attention} issues need attention.`;
    verdict = { status: summary.status, text: summary.unavailable > 0 ? `${issues} ${unread}` : issues };
  } else if (summary.kind === "unreadable") {
    verdict = { status: "unknown", text: "Nothing could be read." };
  } else if (summary.kind === "incomplete") {
    verdict = { status: "unknown", text: `Incomplete. ${unread}` };
  } else if (summary.unavailable > 0) {
    verdict = { status: "unknown", text: `No warnings detected. ${unread}` };
  } else {
    verdict = { status: "ok", text: "No warnings detected." };
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
          <div className="findings" ref={list}>
            {findings.map((finding) => (
              <FindingCard key={finding.id} finding={finding} link={settingsLink(finding)} />
            ))}
          </div>
          <ActivityLog
            title="Windows Security"
            recentStatus={summary.status}
            findings={findings}
            seconds={seconds}
            footer="Read-only check · No settings changed"
          />
        </>
      )}
    </ToolPage>
  );
}
