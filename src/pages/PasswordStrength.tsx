import { useEffect, useMemo, useState } from "react";
import type { Tool } from "../app/tools";
import { analyse, loadAnalyser, type Analyser } from "../app/passwordAnalysis";
import ActivityLog from "../components/ActivityLog";
import FindingCard from "../components/Finding";
import PasswordField from "../components/PasswordField";
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

interface PasswordStrengthProps {
  tool: Tool;
  /* A password sent from another tool. It is entered once, then cleared from the app. */
  handoff: { value: string } | null;
  onHandoffUsed: () => void;
}

export default function PasswordStrength({ tool, handoff, onHandoffUsed }: PasswordStrengthProps) {
  const [password, setPassword] = useState("");
  const [analyser, setAnalyser] = useState<Analyser | null>(null);
  const [failed, setFailed] = useState(false);

  /* A password sent from another tool is entered here. */
  useEffect(() => {
    if (!handoff) return;
    setPassword(handoff.value);
    onHandoffUsed();
  }, [handoff, onHandoffUsed]);

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

  return (
    <ToolPage tool={tool} info={<p>{tool.privacy}</p>}>
      <PasswordField value={password} onChange={setPassword} />

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
