import { useState, type ReactNode } from "react";
import { MAX_LENGTH } from "../app/passwordAnalysis";

/* =========================
   Password Field
   ========================= */

interface PasswordFieldProps {
  value: string;
  onChange: (value: string) => void;
  /* Called when Enter is pressed. */
  onSubmit?: () => void;
  /* Buttons shown after the field, such as Check. */
  children?: ReactNode;
}

/* A password box with a show button and a Clear button, shared by the password tools. */
export default function PasswordField({ value, onChange, onSubmit, children }: PasswordFieldProps) {
  const [visible, setVisible] = useState(false);

  function clear() {
    onChange("");
    setVisible(false);
  }

  return (
    <form
      className="field"
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit?.();
      }}
    >
      <input
        type={visible ? "text" : "password"}
        value={value}
        maxLength={MAX_LENGTH}
        placeholder="Type or paste a password"
        aria-label="Password to check"
        autoComplete="off"
        autoCapitalize="off"
        spellCheck={false}
        onChange={(event) => onChange(event.target.value)}
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
          {visible ? "" : ""}
        </span>
      </button>
      {value && (
        <button type="button" className="button" onClick={clear}>
          Clear
        </button>
      )}
      {children}
    </form>
  );
}
