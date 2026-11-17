import { useEffect, useState } from "react";

/* =========================
   Layout
   ========================= */

/* "classic" is the sidebar layout. "floating" is the experimental one, with floating navigation */
/* and a custom title bar. Classic is the default, so the experiment can always be switched off. */
export type Layout = "classic" | "floating";

const STORAGE_KEY = "tenax.layout";

export function loadLayout(): Layout {
  try {
    return localStorage.getItem(STORAGE_KEY) === "floating" ? "floating" : "classic";
  } catch {
    return "classic";
  }
}

/* Sets data-layout on <html>, which the floating styles are scoped to. */
export function applyLayout(layout: Layout) {
  document.documentElement.dataset.layout = layout;
}

export function useLayout() {
  const [layout, setLayout] = useState<Layout>(loadLayout);

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, layout);
    } catch {
      /* The choice is only lost when the app closes. */
    }
    applyLayout(layout);
  }, [layout]);

  return [layout, setLayout] as const;
}
