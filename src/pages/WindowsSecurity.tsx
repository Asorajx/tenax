import { useState } from "react";
import type { Tool } from "../app/tools";
import FindingCard, { type Finding } from "../components/Finding";
import ToolPage from "../components/ToolPage";

/* =========================
   Sample Data
   ========================= */

/* Placeholder results until the Rust command exists. Not read from this PC. */
const SAMPLE_FINDINGS: Finding[] = [
  {
    id: "firewall",
    status: "warning",
    title: "Firewall is off for public networks",
    detected: "Windows Firewall is on for private networks but off for the Public profile.",
    why: "Public networks such as cafe or airport Wi-Fi are shared with strangers. Without the firewall, other devices on the network can reach services on this PC.",
    action: "Open Windows Security, choose Firewall & network protection, then turn on the firewall for Public network.",
    details: [
      { label: "Domain profile", value: "On" },
      { label: "Private profile", value: "On" },
      { label: "Public profile", value: "Off" },
    ],
  },
  {
    id: "updates",
    status: "info",
    title: "Last update check was 9 days ago",
    detected: "Windows last checked for updates 9 days ago.",
    why: "Updates fix security flaws that attackers actively use. A long gap can mean updates are paused or failing.",
    action: "Open Settings, choose Windows Update, then select Check for updates.",
    details: [
      { label: "Last check", value: "2026-11-07 09:14" },
      { label: "Pending restart", value: "No" },
    ],
  },
  {
    id: "antivirus",
    status: "ok",
    title: "Antivirus is on",
    detected: "Microsoft Defender Antivirus is registered and real-time protection is on.",
    why: "Real-time protection scans files as they are opened. This does not prove the PC is free of malware.",
    details: [
      { label: "Product", value: "Microsoft Defender Antivirus" },
      { label: "Real-time protection", value: "On" },
      { label: "Definitions", value: "Up to date" },
    ],
  },
];


/* =========================
   Windows Security
   ========================= */

type CheckState = "idle" | "loading" | "done";

export default function WindowsSecurity({ tool }: { tool: Tool }) {
  const [state, setState] = useState<CheckState>("idle");

  /* shortcut: fakes the check with a timer, replace with invoke() once the Rust command exists. */
  function runCheck() {
    setState("loading");
    window.setTimeout(() => setState("done"), 900);
  }

  return (
    <ToolPage tool={tool}>
      <p className="notice">
        Preview with sample data. The real check is not built yet, so nothing here reflects this PC.
      </p>

      <div className="panel toolbar">
        <p>Checks antivirus, firewall and Windows Update. Settings are read, never changed.</p>
        <button type="button" className="button button-primary" disabled={state === "loading"} onClick={runCheck}>
          {state === "done" ? "Run again" : "Run check"}
        </button>
      </div>

      {state === "idle" && (
        <div className="empty-state">
          <h3>No results yet</h3>
          <p>Run the check to see sample findings.</p>
        </div>
      )}

      {state === "loading" && (
        <div className="loading" role="status">
          <span>Loading sample findings…</span>
          <div className="loading-bar" />
        </div>
      )}

      {state === "done" && (
        <section className="section">
          <h2>Findings</h2>
          <div className="findings">
            {SAMPLE_FINDINGS.map((finding) => (
              <FindingCard key={finding.id} finding={finding} />
            ))}
          </div>
          <p className="notice">
            These checks read a few settings. Correct settings lower risk but cannot confirm a
            device is secure.
          </p>
        </section>
      )}
    </ToolPage>
  );
}
