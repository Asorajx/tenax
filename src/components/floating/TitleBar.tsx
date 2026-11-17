import { useEffect, useState } from "react";
import { isTauri } from "@tauri-apps/api/core";
import { getCurrentWindow, type Window } from "@tauri-apps/api/window";
import FloatingDock from "./FloatingDock";

/* =========================
   Title Bar
   ========================= */

/* The floating layout's own title bar. It has no background, so it blends into the window. It holds the */
/* navigation. Dragging any empty part moves the window, and double-clicking it maximises, both done by */
/* Tauri through the drag region. The icons and buttons are not part of that region. */
export default function TitleBar({ current, onSelect }: { current: string; onSelect: (id: string) => void }) {
  const [maximized, setMaximized] = useState(false);

  /* The middle button changes between Maximise and Restore with the window. */
  useEffect(() => {
    if (!isTauri()) return;
    const win = getCurrentWindow();
    const update = () => win.isMaximized().then(setMaximized).catch(() => {});
    update();
    const unlisten = win.onResized(update);
    return () => {
      unlisten.then((stop) => stop()).catch(() => {});
    };
  }, []);

  /* Outside the desktop app, such as in a browser preview, the buttons do nothing. */
  const act = (action: (win: Window) => Promise<void>) => () => {
    if (isTauri()) action(getCurrentWindow()).catch(() => {});
  };

  return (
    <header className="titlebar" data-tauri-drag-region>
      <div className="titlebar-brand" aria-hidden="true">
        {/* Same shapes as assets/tenax-icon.svg, coloured by the theme. */}
        <svg className="titlebar-mark" viewBox="11 12 42 41">
          <path
            className="titlebar-mark-shield"
            d="M14 21H50L48.2 32.3C46.8 40.8 40.5 48.1 32 53C23.5 48.1 17.2 40.8 15.8 32.3L14 21Z"
          />
          <path fill="currentColor" d="M11 12H53V21.5H11Z M27 21H37V41.5L32 47.5L27 41.5Z" />
        </svg>
        <span className="titlebar-name">Tenax</span>
      </div>

      <FloatingDock current={current} onSelect={onSelect} />

      <div className="titlebar-controls">
        <button type="button" className="caption-button" aria-label="Minimise" onClick={act((win) => win.minimize())}>
          <span className="caption-glyph" aria-hidden="true">
            {""}
          </span>
        </button>
        <button
          type="button"
          className="caption-button"
          aria-label={maximized ? "Restore" : "Maximise"}
          onClick={act((win) => win.toggleMaximize())}
        >
          <span className="caption-glyph" aria-hidden="true">
            {maximized ? "" : ""}
          </span>
        </button>
        <button
          type="button"
          className="caption-button"
          data-kind="close"
          aria-label="Close"
          onClick={act((win) => win.close())}
        >
          <span className="caption-glyph" aria-hidden="true">
            {""}
          </span>
        </button>
      </div>
    </header>
  );
}
