import { useEffect, useState } from "react";

/* =========================
   Paste Box
   ========================= */

interface PasteBoxProps {
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
  ariaLabel: string;
  /* What the folded-away line calls the pasted text, such as "Email headers provided". */
  summaryLabel: string;
  loading: boolean;
  /* Whether the pasted text has been analysed successfully. */
  done: boolean;
  onAnalyse: () => void;
}

/* The most that can be pasted. Emails are far shorter than this. */
const MAX_LENGTH = 200000;

/* A box for pasted text with Analyse and Clear buttons. Once the text has been analysed it */
/* folds away into one line with an Edit button, so the results get the space. */
export default function PasteBox({
  value,
  onChange,
  placeholder,
  ariaLabel,
  summaryLabel,
  loading,
  done,
  onAnalyse,
}: PasteBoxProps) {
  const [editing, setEditing] = useState(false);

  /* A new result folds the text away again. */
  useEffect(() => {
    if (done) setEditing(false);
  }, [done]);

  const lineCount = value.split("\n").length;

  if (done && !editing) {
    return (
      <div className="input-summary">
        <span>
          {summaryLabel} · {lineCount === 1 ? "1 line" : `${lineCount} lines`}
        </span>
        <button type="button" className="button" onClick={() => setEditing(true)}>
          Edit
        </button>
      </div>
    );
  }

  return (
    <>
      <textarea
        className="text-area"
        value={value}
        maxLength={MAX_LENGTH}
        placeholder={placeholder}
        aria-label={ariaLabel}
        autoComplete="off"
        autoCapitalize="off"
        spellCheck={false}
        onChange={(event) => onChange(event.target.value)}
      />
      <div className="field">
        <button
          type="button"
          className="button button-primary"
          disabled={!value.trim() || loading}
          onClick={onAnalyse}
        >
          {loading ? "Analysing…" : "Analyse"}
        </button>
        {value && (
          <button type="button" className="button" onClick={() => onChange("")}>
            Clear
          </button>
        )}
      </div>
    </>
  );
}
