import { useEffect, useMemo, useState } from "react";
import type { Tool } from "../app/tools";
import { analyse, loadAnalyser, MAX_LENGTH, type Analyser } from "../app/passwordAnalysis";
import ActivityLog from "../components/ActivityLog";
import FindingCard from "../components/Finding";
import ToolPage from "../components/ToolPage";

/* =========================
   Password Strength
   ========================= */

/* What the verdict says for each result. It never claims a password is safe. */
const VERDICTS = {
  risk: "This password is easy to guess.",
  warning: "This password could be guessed with some effort.",
  ok: "No obvious weaknesses found.",
} as const;

export default function PasswordStrength({ tool }: { tool: Tool }) {
  const [password, setPassword] = useState("");
  const [visible, setVisible] = useState(false);
  const [analyser, setAnalyser] = useState<Analyser | null>(null);
  const [failed, setFailed] = useState(false);

  /* The word lists load once, the first time this page opens. */
  useEffect(() => {
    loadAnalyser().then(setAnalyser, () => setFailed(true));
  }, []);

  /* The results update as you type. */
  const findings = useMemo(
    () => (analyser && password ? analyse(analyser, password) : []),
    [analyser, password],
  );

  const status = findings[0]?.status;
  const verdict = status === "risk" || status === "warning" || status === "ok" ? VERDICTS[status] : "";

  function clear() {
    setPassword("");
    setVisible(false);
  }

  return (
    <ToolPage tool={tool} info={<p>{tool.privacy}</p>}>
      <div className="field">
        <input
          type={visible ? "text" : "password"}
          value={password}
          maxLength={MAX_LENGTH}
          placeholder="Type or paste a password"
          aria-label="Password to check"
          autoComplete="off"
          autoCapitalize="off"
          spellCheck={false}
          onChange={(event) => setPassword(event.target.value)}
        />
        <button
          type="button"
          className="icon-button"
          aria-label={visible ? "Hide password" : "Show password"}
          aria-pressed={visible}
          onClick={() => setVisible(!visible)}
        >
          {/* Windows' own icons: View (eye) and Hide (eye with a slash). The key replays the pop. */}
          <span key={String(visible)} className="reveal-glyph" aria-hidden="true">
            {visible ? "\uED1A" : "\uE890"}
          </span>
        </button>
        {password && (
          <button type="button" className="button" onClick={clear}>
            Clear
          </button>
        )}
      </div>

      {failed && (
        <div className="notice" data-tone="error" role="alert">
          The word lists could not be loaded, so the password cannot be analysed.
        </div>
      )}

      {findings.length > 0 && (
        <>
          <p className="verdict" data-status={status} role="status">
            {verdict}
          </p>
          <div className="findings">
            {findings.map((finding) => (
              <FindingCard key={finding.id} finding={finding} />
            ))}
          </div>
          <ActivityLog
            title="Password Strength"
            findings={findings}
            seconds={(findings[0].steps?.[0].ms ?? 0) / 1000}
            footer="Analysed on this device · Password not stored · No data transmitted"
          />
        </>
      )}
    </ToolPage>
  );
}
