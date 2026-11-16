import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { Tool } from "../app/tools";
import ActivityLog from "../components/ActivityLog";
import FindingCard, { type Finding } from "../components/Finding";
import PasswordField from "../components/PasswordField";
import ToolPage from "../components/ToolPage";

/* =========================
   Breached Passwords
   ========================= */

/* What the verdict says for each result. Not being found never means a password is safe. */
const VERDICTS = {
  risk: "This password has appeared in data breaches.",
  ok: "This password wasn't found in the checked breach database.",
  unknown: "The check could not run.",
} as const;

type CheckState = "idle" | "loading" | "done" | "error";

interface BreachedPasswordsProps {
  tool: Tool;
  /* Opens Password Strength with this password already entered. */
  onCheckStrength: (password: string) => void;
}

export default function BreachedPasswords({ tool, onCheckStrength }: BreachedPasswordsProps) {
  const [password, setPassword] = useState("");
  const [state, setState] = useState<CheckState>("idle");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [seconds, setSeconds] = useState(0);
  const [error, setError] = useState("");

  /* Results belong to the password that was checked, so changing it clears them. */
  function changePassword(next: string) {
    setPassword(next);
    if (state === "done" || state === "error") setState("idle");
  }

  /* Asks the Rust backend to hash the password and look it up, then shows what comes back. */
  async function runCheck() {
    if (!password || state === "loading") return;
    setState("loading");
    const started = performance.now();
    try {
      setFindings(await invoke<Finding[]>("check_breached_password", { password }));
      setSeconds((performance.now() - started) / 1000);
      setState("done");
    } catch (reason) {
      setError(String(reason));
      setState("error");
    }
  }

  const status = findings[0]?.status;
  const verdict = status === "risk" || status === "ok" || status === "unknown" ? VERDICTS[status] : "";

  return (
    <ToolPage tool={tool} info={<p>{tool.privacy}</p>}>
      <PasswordField value={password} onChange={changePassword} onSubmit={runCheck}>
        <button
          type="submit"
          className="button button-primary"
          disabled={!password || state === "loading"}
        >
          {state === "loading" ? "Checking…" : "Check"}
        </button>
      </PasswordField>

      {state === "error" && (
        <div className="notice" data-tone="error" role="alert">
          The check could not run, so there are no findings to show. {error}
        </div>
      )}

      {state === "done" && (
        <>
          <p className="verdict" data-status={status} role="status">
            {verdict}
          </p>
          <div className="findings">
            {findings.map((finding) => (
              <FindingCard
                key={finding.id}
                finding={finding}
                link={{ text: "Password Strength", onClick: () => onCheckStrength(password) }}
              />
            ))}
          </div>
          <ActivityLog
            title="Breached Passwords"
            findings={findings}
            seconds={seconds}
            footer="Only a partial hash (5 characters) was sent · Password never transmitted"
          />
        </>
      )}
    </ToolPage>
  );
}
