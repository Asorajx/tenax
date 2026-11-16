import { useCallback, useEffect, useRef, useState } from "react";
import { useTheme } from "./app/theme";
import { ALL_TOOLS, TOOL_GROUPS } from "./app/tools";
import Sidebar from "./components/Sidebar";
import BreachedPasswords from "./pages/BreachedPasswords";
import EmailHeaders from "./pages/EmailHeaders";
import Home from "./pages/Home";
import PasswordStrength from "./pages/PasswordStrength";
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

  /* A password sent from one tool to another. It is cleared as soon as the other tool has it. */
  const [handoff, setHandoff] = useState<{ password: string } | null>(null);
  const clearHandoff = useCallback(() => setHandoff(null), []);
  function checkStrength(password: string) {
    setHandoff({ password });
    setPage("password-strength");
  }

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

  /* Every page that has been opened stays loaded, so a tool keeps its results */
  /* when you switch to another page and come back. */
  const [opened, setOpened] = useState([page]);
  if (!opened.includes(page)) setOpened([...opened, page]);

  /* Each newly shown page starts scrolled to the top. */
  const content = useRef<HTMLElement>(null);
  useEffect(() => {
    content.current?.scrollTo(0, 0);
  }, [page]);

  function renderPage(id: string) {
    const tool = ALL_TOOLS.find((candidate) => candidate.id === id);

    if (id === "home") return <Home onNavigate={setPage} />;
    if (id === "settings") return <Settings theme={theme} onThemeChange={setTheme} />;
    if (tool?.id === "email-headers") return <EmailHeaders tool={tool} />;
    if (tool?.id === "password-breach") return <BreachedPasswords tool={tool} onCheckStrength={checkStrength} />;
    if (tool?.id === "password-strength") return <PasswordStrength tool={tool} handoff={handoff} onHandoffUsed={clearHandoff} />;
    if (tool?.id === "windows-security") return <WindowsSecurity tool={tool} />;
    return tool && <PlannedTool tool={tool} />;
  }

  return (
    <div className="app">
      <Sidebar page={page} onNavigate={setPage} />

      <main className="content" ref={content}>
        {opened.map((id) => (
          <div key={id} className="content-inner" hidden={id !== page}>
            {renderPage(id)}
          </div>
        ))}
      </main>
    </div>
  );
}
