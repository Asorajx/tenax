import { useEffect, useState, type CSSProperties } from "react";

/* =========================
   Splash
   ========================= */

/* The logo plays once on launch, then fades out to the app. Any click or key skips it. */
const SHOW_MS = 2750;
const FADE_MS = 300;

/* Sparks fly out from where the stem meets the bar. Angles run along and below the bar so they show on the background. */
const SPARKS = Array.from({ length: 12 }, (_, index) => {
  const angle = ((-15 + (index * 210) / 11) * Math.PI) / 180;
  const distance = index % 2 ? 20 : 32;
  return { x: Math.cos(angle) * distance, y: Math.sin(angle) * distance };
});

export default function Splash() {
  const [stage, setStage] = useState<"show" | "leave" | "done">(
    window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "done" : "show",
  );

  useEffect(() => {
    if (stage === "done") return;

    const skip = () => setStage((current) => (current === "show" ? "leave" : current));
    const timer = window.setTimeout(skip, stage === "show" ? SHOW_MS : 0);
    const finish = stage === "leave" ? window.setTimeout(() => setStage("done"), FADE_MS) : 0;

    window.addEventListener("pointerdown", skip);
    window.addEventListener("keydown", skip);
    return () => {
      window.clearTimeout(timer);
      window.clearTimeout(finish);
      window.removeEventListener("pointerdown", skip);
      window.removeEventListener("keydown", skip);
    };
  }, [stage]);

  if (stage === "done") return null;

  return (
    <div className="splash" data-leaving={stage === "leave" || undefined} aria-hidden="true">
      {/* Same shapes as the title bar mark. The bar zooms in, the stem hits it, then the shield is revealed. */}
      <div className="splash-logo">
        <svg className="splash-mark" viewBox="11 12 42 41">
          <path
            className="splash-shield"
            d="M14 21H50L48.2 32.3C46.8 40.8 40.5 48.1 32 53C23.5 48.1 17.2 40.8 15.8 32.3L14 21Z"
          />
          <path className="splash-bar" d="M11 12H53V21.5H11Z" />
          <path className="splash-stem" d="M27 21H37V41.5L32 47.5L27 41.5Z" />
          {SPARKS.map((spark, index) => (
            <circle
              key={index}
              className="splash-spark"
              cx="32"
              cy="21.5"
              r={index % 2 ? 1 : 1.5}
              style={{ "--x": `${spark.x}px`, "--y": `${spark.y}px` } as CSSProperties}
            />
          ))}
        </svg>
        <div className="splash-word">
          <span>Tenax</span>
        </div>
      </div>
    </div>
  );
}
