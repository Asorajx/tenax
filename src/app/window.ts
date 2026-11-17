import { useEffect } from "react";
import { isTauri } from "@tauri-apps/api/core";
import { Effect, getCurrentWindow } from "@tauri-apps/api/window";
import type { Layout } from "./layout";
import type { Theme } from "./theme";

/* =========================
   Window Mode
   ========================= */

/* The floating layout draws its own title bar and asks Windows for an Acrylic backdrop. The classic */
/* layout uses the normal Windows title bar and no backdrop. The window starts hidden, so this is */
/* settled before it appears, and a failure at any step only leaves the solid look. */

/* Whether the user has asked Windows for less transparency. Acrylic is then not requested. */
function prefersSolid() {
  return (
    window.matchMedia("(prefers-reduced-transparency: reduce)").matches ||
    window.matchMedia("(forced-colors: active)").matches
  );
}

/* Sets data-glass on <html>. "on" lets the floating styles show the window behind through the app. */
function setGlass(on: boolean) {
  document.documentElement.dataset.glass = on ? "on" : "off";
}

async function apply(layout: Layout, theme: Theme) {
  setGlass(false);
  if (!isTauri()) return;

  const win = getCurrentWindow();
  try {
    /* On Windows 11 the Acrylic colour follows the window's own theme, not a colour set here. */
    await win.setTheme(theme === "system" ? null : theme);
  } catch {
    /* The backdrop is then drawn in the system theme. */
  }

  try {
    if (layout === "floating") {
      await win.setDecorations(false);
      if (!prefersSolid()) {
        await win.setEffects({ effects: [Effect.Acrylic] });
        setGlass(true);
      }
    } else {
      await win.setDecorations(true);
      await win.setEffects({ effects: [] });
    }
  } catch {
    /* Acrylic is not available here, so the app stays solid. */
    setGlass(false);
  }
}

/* Applies the window mode whenever the layout or theme changes, then shows the window. */
export function useWindowMode(layout: Layout, theme: Theme) {
  useEffect(() => {
    let cancelled = false;
    apply(layout, theme).finally(() => {
      if (!cancelled && isTauri()) getCurrentWindow().show().catch(() => {});
    });
    return () => {
      cancelled = true;
    };
  }, [layout, theme]);
}
