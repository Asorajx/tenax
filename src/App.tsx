import { useEffect, useState } from "react";
import { useTheme } from "./app/theme";
import { ALL_TOOLS, TOOL_GROUPS } from "./app/tools";
import Sidebar from "./components/Sidebar";
import Home from "./pages/Home";
import PlannedTool from "./pages/PlannedTool";
import Settings from "./pages/Settings";
import WindowsSecurity from "./pages/WindowsSecurity";

/* =========================
   App
   ========================= */

/* Ctrl + 1 opens Home, Ctrl + 2 to 5 open the first tool of each group. */
const SHORTCUT_PAGES = ["home", ...TOOL_GROUPS.map((group) => group.tools[0].id)];

export default function App() {
  /* The current page is plain state, so no router is needed. */
  const [page, setPage] = useState("home");
  const [theme, setTheme] = useTheme();

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (!event.ctrlKey || event.altKey) return;

      const shortcutPage = SHORTCUT_PAGES[Number(event.key) - 1];
      if (event.shiftKey && event.key.toLowerCase() === "l") {
        setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
      } else if (event.key === ",") {
        setPage("settings");
      } else if (shortcutPage && !event.shiftKey) {
        setPage(shortcutPage);
      } else {
        return;
      }
      event.preventDefault();
    }

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [setTheme]);

  const tool = ALL_TOOLS.find((candidate) => candidate.id === page);

  return (
    <div className="app">
      <Sidebar page={page} onNavigate={setPage} />

      {/* The key resets scroll position and page state on navigation. */}
      <main className="content" key={page}>
        <div className="content-inner">
          {page === "home" && <Home onNavigate={setPage} />}
          {page === "settings" && <Settings theme={theme} onThemeChange={setTheme} />}
          {tool?.id === "windows-security" && <WindowsSecurity tool={tool} />}
          {tool && tool.id !== "windows-security" && <PlannedTool tool={tool} />}
        </div>
      </main>
    </div>
  );
}
