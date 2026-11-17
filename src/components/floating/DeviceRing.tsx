import type { DevicePhase } from "../../app/deviceCheck";
import type { Finding, FindingStatus } from "../Finding";

/* =========================
   Device Ring
   ========================= */

/* The three checks the Windows Security tool makes, in the order they sit around the ring. Each has */
/* a segment of its own, so one check never colours another. The short name is written on the ring. */
export const DEVICE_CHECKS = [
  { id: "antivirus", label: "Antivirus", short: "Antivirus", from: -80, to: 20 },
  { id: "firewall", label: "Firewall", short: "Firewall", from: 40, to: 140 },
  { id: "updates", label: "Windows Update", short: "Updates", from: 160, to: 260 },
] as const;

/* What each result is called in words. There is no score, and "not checked" is never a good result. */
export function statusWord(status: string) {
  switch (status) {
    case "ok":
      return "no issue found";
    case "info":
      return "worth a look";
    case "warning":
    case "risk":
      return "needs attention";
    case "limited":
    case "unknown":
      return "could not be checked";
    default:
      return "not checked";
  }
}

/* A check that could not be read: it failed, or it only partly ran. */
function unreadable(status: string) {
  return status === "unknown" || status === "limited";
}

type DeviceKind = "attention" | "unreadable" | "incomplete" | "notes" | "clear";

/* What the Windows Security results add up to. Whether there are warnings is kept apart from whether */
/* everything could be read, and warnings always come first. The Home line, the Recent dot and the */
/* page's own sentence all use this, so they cannot disagree. It never says the PC is safe. */
/*   attention    a warning or a risk                          */
/*   unreadable   nothing could be read                        */
/*   incomplete   one of the three ring checks could not be read, so the line cannot say "no warnings" */
/*   notes        no warnings, but something is worth a look   */
/*   clear        no warnings, though other checks may be unavailable */
export function deviceStatus(findings: Finding[]) {
  const attention = findings.filter((finding) => finding.status === "warning" || finding.status === "risk");
  const found = (id: string) => findings.find((finding) => finding.id === id);
  /* A ring check that is missing counts as not read. */
  const missing = DEVICE_CHECKS.filter((check) => !found(check.id)).length;
  const coreUnread = DEVICE_CHECKS.some((check) => {
    const finding = found(check.id);
    return !finding || unreadable(finding.status);
  });
  const unavailable = findings.filter((finding) => unreadable(finding.status)).length + missing;
  const readable = findings.filter((finding) => !unreadable(finding.status)).length;

  let kind: DeviceKind;
  let title: string;
  let status: FindingStatus;
  if (attention.length > 0) {
    kind = "attention";
    title = "Needs attention";
    status = attention.some((finding) => finding.status === "risk") ? "risk" : "warning";
  } else if (readable === 0) {
    kind = "unreadable";
    title = "Could not be read";
    status = "limited";
  } else if (coreUnread) {
    kind = "incomplete";
    title = "Incomplete";
    status = "limited";
  } else if (findings.some((finding) => finding.status === "info")) {
    kind = "notes";
    title = "Worth a look";
    status = "info";
  } else {
    kind = "clear";
    title = "No warnings detected";
    /* Grey, not green, when something could not be read, so it never looks fully verified. */
    status = unavailable > 0 ? "limited" : "ok";
  }
  return { kind, title, status, attention: attention.length, unavailable };
}

/* The one line in the middle. It speaks for every check the tool made, not only the three on the ring. */
function ringSummary(phase: DevicePhase, findings: Finding[]) {
  if (phase === "loading") return { title: "Checking" };
  if (phase === "error") return { title: "Could not check" };
  if (phase !== "done") return { title: "Not checked" };
  return { title: deviceStatus(findings).title };
}

/* The findings that have no segment on the ring. The Home screen lists them beside the ring. They are */
/* taken from the findings, so a new Windows Security card is included without any change here. */
export function extraChecks(phase: DevicePhase, findings: Finding[]) {
  if (phase !== "done") return [];
  return findings.filter((finding) => !DEVICE_CHECKS.some((check) => check.id === finding.id));
}

/* A point on the ring, for an angle in degrees measured clockwise from the right. */
function point(angle: number, radius: number) {
  const radians = (angle * Math.PI) / 180;
  return [140 + radius * Math.cos(radians), 110 + radius * Math.sin(radians)];
}

function arc(from: number, to: number, radius: number) {
  const [x1, y1] = point(from, radius);
  const [x2, y2] = point(to, radius);
  return `M ${x1.toFixed(2)} ${y1.toFixed(2)} A ${radius} ${radius} 0 0 1 ${x2.toFixed(2)} ${y2.toFixed(2)}`;
}

/* A long title is split over two lines, at the space nearest its middle, so it stays inside the ring. */
function titleLines(title: string) {
  if (title.length <= 16) return [title];
  const middle = title.length / 2;
  let cut = -1;
  for (let at = title.indexOf(" "); at !== -1; at = title.indexOf(" ", at + 1)) {
    if (cut === -1 || Math.abs(at - middle) < Math.abs(cut - middle)) cut = at;
  }
  return cut === -1 ? [title] : [title.slice(0, cut), title.slice(cut + 1)];
}

interface DeviceRingProps {
  phase: DevicePhase;
  findings: Finding[];
}

/* A ring in three separate segments, one for each check, coloured by what that check found. Before the */
/* settings are read, every segment is dim. A segment that could not be read is dotted, so it is not */
/* mistaken for one that was checked. */
export default function DeviceRing({ phase, findings }: DeviceRingProps) {
  const summary = ringSummary(phase, findings);
  const statusOf = (id: string) => (phase === "done" ? (findings.find((finding) => finding.id === id)?.status ?? "none") : "none");

  const description = DEVICE_CHECKS.map((check) => `${check.label} ${statusWord(statusOf(check.id))}`).join(", ");
  const lines = titleLines(summary.title);
  const unavailable = phase === "done" ? deviceStatus(findings).unavailable : 0;
  const unavailableText = unavailable > 0 ? ` ${unavailable} ${unavailable === 1 ? "check" : "checks"} unavailable.` : "";

  return (
    <svg
      className="ring"
      viewBox="0 0 280 220"
      data-phase={phase}
      role="img"
      aria-label={`Device security. ${summary.title}. ${description}.${unavailableText}`}
    >
      {DEVICE_CHECKS.map((check, index) => (
        <path
          key={check.id}
          className="ring-segment"
          pathLength={1}
          data-status={statusOf(check.id)}
          style={{ animationDelay: `${index * 0.25}s` }}
          d={arc(check.from, check.to, 76)}
        />
      ))}

      {DEVICE_CHECKS.map((check) => {
        const middle = (check.from + check.to) / 2;
        const [x, y] = point(middle, 96);
        const anchor = Math.abs(Math.cos((middle * Math.PI) / 180)) < 0.3 ? "middle" : Math.cos((middle * Math.PI) / 180) > 0 ? "start" : "end";
        return (
          <text key={check.id} className="ring-label" x={x} y={y + 4} textAnchor={anchor}>
            {check.short}
          </text>
        );
      })}

      <text key={summary.title} className="ring-title" x="140" y={lines.length > 1 ? 94 : 108} textAnchor="middle">
        {lines.map((line, index) => (
          <tspan key={line} x="140" dy={index === 0 ? 0 : 18}>
            {line}
          </tspan>
        ))}
      </text>
    </svg>
  );
}
