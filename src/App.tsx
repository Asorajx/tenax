import { useCallback, useEffect, useRef, useState } from "react";
import { useTheme } from "./app/theme";
import { ALL_TOOLS, TOOL_GROUPS } from "./app/tools";
import Sidebar from "./components/Sidebar";
import BreachedPasswords from "./pages/BreachedPasswords";
import DnsLookup from "./pages/DnsLookup";
import IpInformation from "./pages/IpInformation";
import TlsCertificate from "./pages/TlsCertificate";
import EmailHeaders from "./pages/EmailHeaders";
import EmailScam from "./pages/EmailScam";
import Home from "./pages/Home";
import PasswordStrength from "./pages/PasswordStrength";
import PlannedTool from "./pages/PlannedTool";
import Settings from "./pages/Settings";
import UrlChecker from "./pages/UrlChecker";
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

  /* A value sent from one tool to another, such as a password or a link. It is kept in memory */
  /* only, and cleared as soon as the other tool has it. */
  const [handoff, setHandoff] = useState<{ tool: string; value: string } | null>(null);
  const clearHandoff = useCallback(() => setHandoff(null), []);
  function sendTo(tool: string, value: string) {
    setHandoff({ tool, value });
    setPage(tool);
  }

  /* The Email Scam Checker can send a link to the URL Checker once that tool is built. Until */
  /* then it is not offered, so there is no button that leads nowhere. */
  const urlChecker = ALL_TOOLS.find((candidate) => candidate.id === "url-check");
  const analyseUrl = urlChecker?.ready ? (url: string) => sendTo("url-check", url) : undefined;

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
    if (tool?.id === "url-check") {
      return (
        <UrlChecker
          tool={tool}
          handoff={handoff?.tool === "url-check" ? handoff : null}
          onHandoffUsed={clearHandoff}
        />
      );
    }
    if (tool?.id === "dns-lookup") return <DnsLookup tool={tool} />;
    if (tool?.id === "ip-info") return <IpInformation tool={tool} />;
    if (tool?.id === "tls-check") return <TlsCertificate tool={tool} />;
    if (tool?.id === "email-scam") return <EmailScam tool={tool} onAnalyseUrl={analyseUrl} />;
    if (tool?.id === "email-headers") return <EmailHeaders tool={tool} />;
    if (tool?.id === "password-breach") return <BreachedPasswords tool={tool} onCheckStrength={(password) => sendTo("password-strength", password)} />;
    if (tool?.id === "password-strength") return <PasswordStrength
          tool={tool}
          handoff={handoff?.tool === "password-strength" ? handoff : null}
          onHandoffUsed={clearHandoff}
        />;
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
