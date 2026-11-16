import { useState } from "react";

/* =========================
   Copy Button
   ========================= */

interface CopyButtonProps {
  text: string;
  /* What a screen reader hears, such as "Copy link". */
  ariaLabel: string;
}

/* A small button that copies some text and says so for a moment. */
export default function CopyButton({ text, ariaLabel }: CopyButtonProps) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      /* The clipboard can be blocked, so the button simply stays as it is. */
    }
  }

  return (
    <button type="button" className="button button-small" aria-label={ariaLabel} onClick={copy}>
      {copied ? "Copied" : "Copy"}
    </button>
  );
}
