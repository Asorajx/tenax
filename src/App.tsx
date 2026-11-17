import { useCallback, useEffect, useState } from "react";
import { useTheme } from "./app/theme";
import { useWindowMode } from "./app/window";
import { useLastTools, workspaceOf, WORKSPACES } from "./app/workspaces";
import { ALL_TOOLS } from "./app/tools";
import FindBar from "./components/FindBar";
import FloatingShell from "./components/floating/FloatingShell";
import BreachedPasswords from "./pages/BreachedPasswords";
import DnsLookup from "./pages/DnsLookup";
import IpInformation from "./pages/IpInformation";
import TlsCertificate from "./pages/TlsCertificate";
import EmailHeaders from "./pages/EmailHeaders";
import EmailScam from "./pages/EmailScam";
import HomeMinimal from "./pages/HomeMinimal";
import PasswordStrength from "./pages/PasswordStrength";
import QrChecker from "./pages/QrChecker";
import Settings from "./pages/Settings";
import UrlChecker from "./pages/UrlChecker";
import WindowsSecurity from "./pages/WindowsSecurity";

/* =========================
   App
   ========================= */

/* Ctrl + 1 opens Home, Ctrl + 2 to 5 open the first tool of each workspace. Ctrl + Tab and */
/* Ctrl + Shift + Tab go round those five in order. */
const SHORTCUT_PAGES = ["home", ...WORKSPACES.map((workspace) => workspace.tools[0].id)];

export default function App() {
  /* The current page is plain state, so no router is needed. */
  const [page, setPage] = useState("home");
  const toolFor = useLastTools(page);
  const [theme, setTheme] = useTheme();

  /* The section of Settings that is open. */
  const [settingsTab, setSettingsTab] = useState("general");

  /* The window follows the theme: its title bar and backdrop. */
  useWindowMode(theme);

  /* A value sent from one tool to another, such as a password or a link. It is kept in memory */
  /* only, and cleared as soon as the other tool has it. */
  const [handoff, setHandoff] = useState<{ tool: string; value: string } | null>(null);
  const clearHandoff = useCallback(() => setHandoff(null), []);
  function sendTo(tool: string, value: string) {
    setHandoff({ tool, value });
    setPage(tool);
  }

  /* The Home screen can open Windows Security at one card. The card is scrolled to once, then forgotten. */
  const [focusFinding, setFocusFinding] = useState<string | null>(null);
  const clearFocusFinding = useCallback(() => setFocusFinding(null), []);
  function openFinding(finding: string) {
    setFocusFinding(finding);
    setPage("windows-security");
  }

  /* The Email Scam Checker can send a link to the URL Checker once that tool is built. Until */
  /* then it is not offered, so there is no button that leads nowhere. */
  const urlChecker = ALL_TOOLS.find((candidate) => candidate.id === "url-check");
  const analyseUrl = urlChecker?.ready ? (url: string) => sendTo("url-check", url) : undefined;

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (!event.ctrlKey || event.altKey) return;

      const shortcutPage = SHORTCUT_PAGES[Number(event.key) - 1];
      if (event.key === "Tab") {
        /* Round the five sections: Home, then the four workspaces. From Settings, forwards goes to Home and */
        /* backwards to the last one. A workspace comes back to the tool last open in it. */
        const sections = SHORTCUT_PAGES;
        const here =
          page === "home"
            ? 0
            : WORKSPACES.findIndex((workspace) => workspace.id === workspaceOf(page)?.id) + 1 || -1;
        const next =
          here === -1
            ? event.shiftKey
              ? sections.length - 1
              : 0
            : (here + (event.shiftKey ? -1 : 1) + sections.length) % sections.length;
        setPage(next > 0 ? toolFor(WORKSPACES[next - 1].id) : sections[next]);
      } else if (event.shiftKey && event.key.toLowerCase() === "l") {
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
  }, [setTheme, page, toolFor]);

  /* Every page that has been opened stays loaded, so a tool keeps its results */
  /* when you switch to another page and come back. */
  const [opened, setOpened] = useState([page]);
  if (!opened.includes(page)) setOpened([...opened, page]);

  function renderPage(id: string) {
    const tool = ALL_TOOLS.find((candidate) => candidate.id === id);

    if (id === "home") {
      return <HomeMinimal onOpen={(workspace) => setPage(toolFor(workspace))} onOpenTool={setPage} onOpenFinding={openFinding} />;
    }
    if (id === "settings") {
      return <Settings theme={theme} onThemeChange={setTheme} tab={settingsTab} onTabChange={setSettingsTab} />;
    }
    if (tool?.id === "url-check") {
      return (
        <UrlChecker
          tool={tool}
          handoff={handoff?.tool === "url-check" ? handoff : null}
          onHandoffUsed={clearHandoff}
        />
      );
    }
    if (tool?.id === "qr-check") return <QrChecker tool={tool} />;
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
    if (tool?.id === "windows-security") return <WindowsSecurity tool={tool} focus={focusFinding} onFocused={clearFocusFinding} />;
    return null;
  }

  const pages = opened.map((id) => (
    <div key={id} className="content-inner" hidden={id !== page}>
      {renderPage(id)}
    </div>
  ));

  return (
    <>
      <FloatingShell page={page} onNavigate={setPage} toolFor={toolFor}>
        {pages}
      </FloatingShell>
      <FindBar />
    </>
  );
}
