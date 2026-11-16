import { useEffect, useState } from "react";

/* =========================
   Theme
   ========================= */

export type Theme = "dark" | "light" | "system";

const STORAGE_KEY = "tenax.theme";
const LIGHT_QUERY = "(prefers-color-scheme: light)";

export function loadTheme(): Theme {
  const saved = localStorage.getItem(STORAGE_KEY);
  return saved === "light" || saved === "system" ? saved : "dark";
}

/* Sets data-theme on <html>, which switches the colour tokens. */
export function applyTheme(theme: Theme) {
  const systemTheme = window.matchMedia(LIGHT_QUERY).matches ? "light" : "dark";
  document.documentElement.dataset.theme = theme === "system" ? systemTheme : theme;
}

export function useTheme() {
  const [theme, setTheme] = useState<Theme>(loadTheme);

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, theme);
    applyTheme(theme);
    if (theme !== "system") return;

    /* Follow Windows when it switches between light and dark. */
    const query = window.matchMedia(LIGHT_QUERY);
    const onChange = () => applyTheme("system");
    query.addEventListener("change", onChange);
    return () => query.removeEventListener("change", onChange);
  }, [theme]);

  return [theme, setTheme] as const;
}
