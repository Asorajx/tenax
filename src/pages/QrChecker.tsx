import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { ImageProblem, MAX_CODES, readQrCodes } from "../app/qrImage";
import type { Tool } from "../app/tools";
import ActivityLog from "../components/ActivityLog";
import FindingCard, { type Finding } from "../components/Finding";
import ToolPage from "../components/ToolPage";
import VerdictBlock, { type Verdict } from "../components/VerdictBlock";

/* =========================
   QR Code Checker
   ========================= */

interface QrReport {
  verdict: Verdict;
  findings: Finding[];
}

type CheckState = "idle" | "loading" | "done" | "error";

export default function QrChecker({ tool }: { tool: Tool }) {
  const [state, setState] = useState<CheckState>("idle");
  const [report, setReport] = useState<QrReport | null>(null);
  const [seconds, setSeconds] = useState(0);
  const [error, setError] = useState("");
  /* Said above the results when they may not be everything in the image. */
  const [note, setNote] = useState("");
  const root = useRef<HTMLDivElement>(null);
  const picker = useRef<HTMLInputElement>(null);

  /* Only the newest image may show its result, in case two are given close together. */
  const latest = useRef(0);

  /* Reads the codes out of the image on this PC, then asks the backend what they are. Nothing in a */
  /* code is opened, and the image itself never leaves this page. */
  async function check(image: Blob) {
    const mine = ++latest.current;
    setState("loading");
    const started = performance.now();
    try {
      const { codes, incomplete } = await readQrCodes(image);
      if (mine !== latest.current) return;
      /* A code that could not be read is not a safe one, and the message says so. */
      if (codes.length === 0) {
        throw new ImageProblem(
          incomplete
            ? "The search ran out of time before it found a QR code. That does not mean the image is safe."
            : "No readable QR code was found in that image. That does not mean it is safe.",
        );
      }
      const result = await invoke<QrReport>("check_qr", { payloads: codes });
      if (mine !== latest.current) return;
      setReport(result);
      setNote(
        incomplete
          ? "The search stopped early, so other codes in the image may not have been read."
          : codes.length >= MAX_CODES
            ? `Only the first ${MAX_CODES} codes were read.`
            : "",
      );
      setSeconds((performance.now() - started) / 1000);
      setState("done");
    } catch (reason) {
      if (mine !== latest.current) return;
      setError(reason instanceof ImageProblem ? reason.message : String(reason));
      setState("error");
    }
  }

  /* Pasting an image, such as a screenshot, checks it. Every page that has been opened stays loaded, */
  /* so this only acts while this page is showing, and never while a text box has the focus. */
  useEffect(() => {
    function onPaste(event: ClipboardEvent) {
      if (!root.current || root.current.offsetParent === null) return;
      if (event.target instanceof Element && event.target.closest("input, textarea, [contenteditable]")) return;
      const image = [...(event.clipboardData?.items ?? [])]
        .find((item) => item.kind === "file" && item.type.startsWith("image/"))
        ?.getAsFile();
      if (!image) return;
      event.preventDefault();
      void check(image);
    }

    document.addEventListener("paste", onPaste);
    return () => document.removeEventListener("paste", onPaste);
  }, []);

  /* The file picker is hidden, and the button opens it. The same file can be chosen twice in a row. */
  function chosen(files: FileList | null) {
    const image = files?.[0];
    if (picker.current) picker.current.value = "";
    if (image) void check(image);
  }

  const again = state === "done" && (
    <button type="button" className="button button-primary" onClick={() => picker.current?.click()}>
      Check another
    </button>
  );

  return (
    <ToolPage tool={tool} info={<p>{tool.privacy}</p>} action={again}>
      <div className="qr-checker" ref={root}>
        <input
          ref={picker}
          type="file"
          accept="image/png,image/jpeg"
          hidden
          aria-label="QR code image"
          onChange={(event) => chosen(event.target.files)}
        />

        {state === "error" && (
          <div className="notice" data-tone="error" role="alert">
            {error}
          </div>
        )}

        {state !== "done" && (
          <div className="hero" data-phase={state === "loading" ? "loading" : "idle"}>
            <div className="hero-icon">
              <tool.icon size={28} strokeWidth={1.5} aria-hidden="true" />
              <tool.icon className="hero-icon-fill" size={28} strokeWidth={1.5} aria-hidden="true" />
            </div>
            <div className="hero-text" role="status">
              <h2>{state === "loading" ? "Reading the image…" : "Paste or choose a QR code image"}</h2>
            </div>
            <button
              type="button"
              className="button button-primary button-large"
              disabled={state === "loading"}
              onClick={() => picker.current?.click()}
            >
              Choose image
            </button>
          </div>
        )}

        {state === "done" && report && (
          <>
            {note && (
              <div className="notice" role="status">
                {note}
              </div>
            )}
            <VerdictBlock verdict={report.verdict} />
            <div className="findings">
              {report.findings.map((finding) => (
                /* What the code holds is the point, so its own card starts open. The address cards do not. */
                <FindingCard key={finding.id} finding={finding} expanded={/^qr-\d+$/.test(finding.id)} />
              ))}
            </div>
            <ActivityLog
              title="QR Code Checker"
              findings={report.findings}
              seconds={seconds}
              result={report.verdict.headline}
              footer="Read locally · Nothing opened · No data sent"
            />
          </>
        )}
      </div>
    </ToolPage>
  );
}
