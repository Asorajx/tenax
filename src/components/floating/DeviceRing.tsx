import type { DevicePhase } from "../../app/deviceCheck";
import type { Finding } from "../Finding";

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

/* The one line in the middle. It only speaks for the three settings, and never says the PC is safe. */
export function ringSummary(phase: DevicePhase, findings: Finding[]) {
  if (phase === "loading") return { title: "Checking" };
  if (phase === "error") return { title: "Could not check" };
  if (phase !== "done") return { title: "Not checked" };

  const statuses = DEVICE_CHECKS.map((check) => findings.find((finding) => finding.id === check.id)?.status);
  if (statuses.some((status) => status === "warning" || status === "risk")) {
    return { title: "Needs attention" };
  }
  if (statuses.some((status) => status === undefined || status === "unknown" || status === "limited")) {
    return { title: "Incomplete" };
  }
  if (statuses.some((status) => status === "info")) {
    return { title: "Worth a look" };
  }
  return { title: "Nothing flagged" };
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

  return (
    <svg
      className="ring"
      viewBox="0 0 280 220"
      data-phase={phase}
      role="img"
      aria-label={`Device security. ${summary.title}. ${description}.`}
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

      <text key={summary.title} className="ring-title" x="140" y="108" textAnchor="middle">
        {summary.title}
      </text>
    </svg>
  );
}
