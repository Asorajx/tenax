import type { Layout } from "../app/layout";
import { SETTINGS_TABS } from "../app/settingsTabs";
import type { Theme } from "../app/theme";
import About from "./About";

/* =========================
   Settings
   ========================= */

const THEMES: { value: Theme; label: string }[] = [
  { value: "dark", label: "Dark" },
  { value: "light", label: "Light" },
  { value: "system", label: "System" },
];

const LAYOUTS: { value: Layout; label: string }[] = [
  { value: "classic", label: "Classic" },
  { value: "floating", label: "Floating" },
];

const SHORTCUTS = [
  { keys: "Ctrl + 1", action: "Home" },
  { keys: "Ctrl + 2 to 5", action: "First tool in each group" },
  { keys: "Ctrl + Tab", action: "Next section (Shift for previous)" },
  { keys: "Ctrl + F", action: "Find in page" },
  { keys: "Ctrl + ,", action: "Settings" },
  { keys: "Ctrl + Shift + L", action: "Switch between light and dark" },
];

/* The keys for moving through the navigation depend on the layout. */
const MOVE_KEYS = {
  classic: { keys: "Up / Down", action: "Move through the sidebar" },
  floating: { keys: "Left / Right", action: "Move through the navigation" },
};

interface SettingsProps {
  theme: Theme;
  onThemeChange: (theme: Theme) => void;
  layout: Layout;
  onLayoutChange: (layout: Layout) => void;
  /* The section that is open, chosen in the tab bar. */
  tab: string;
  onTabChange: (tab: string) => void;
}

export default function Settings({ theme, onThemeChange, layout, onLayoutChange, tab, onTabChange }: SettingsProps) {
  return (
    <>
      <header className="page-header">
        <h1>Settings</h1>
      </header>

      <div className="settings">
        <nav className="settings-nav" aria-label="Settings sections">
          <ul>
            {SETTINGS_TABS.map((item) => (
              <li key={item.id}>
                <button type="button" aria-current={item.id === tab ? "page" : undefined} onClick={() => onTabChange(item.id)}>
                  {item.label}
                </button>
              </li>
            ))}
          </ul>
        </nav>

        {/* A new section reveals itself, as the tool pages do. */}
        <div className="settings-content" key={tab}>
          {tab === "general" && (
            <>
              <section className="section">
                <h2>Appearance</h2>
                <div className="panel">
                  <div className="row">
                    <span className="row-text">
                      <span className="row-title" id="theme-label">Theme</span>
                    </span>
                    <div className="segmented" role="radiogroup" aria-labelledby="theme-label">
                      {THEMES.map((option) => (
                        <label key={option.value}>
                          <input
                            type="radio"
                            name="theme"
                            checked={theme === option.value}
                            onChange={() => onThemeChange(option.value)}
                          />
                          {option.label}
                        </label>
                      ))}
                    </div>
                  </div>
                  <div className="row">
                    <span className="row-text">
                      <span className="row-title" id="layout-label">Layout</span>
                    </span>
                    <div className="segmented" role="radiogroup" aria-labelledby="layout-label">
                      {LAYOUTS.map((option) => (
                        <label key={option.value}>
                          <input
                            type="radio"
                            name="layout"
                            checked={layout === option.value}
                            onChange={() => onLayoutChange(option.value)}
                          />
                          {option.label}
                        </label>
                      ))}
                    </div>
                  </div>
                </div>
              </section>
              <section className="section">
                <h2>Keyboard shortcuts</h2>
                <div className="panel">
                  {[...SHORTCUTS, MOVE_KEYS[layout]].map((shortcut) => (
                    <div key={shortcut.keys} className="row">
                      <span>{shortcut.action}</span>
                      <kbd>{shortcut.keys}</kbd>
                    </div>
                  ))}
                </div>
              </section>
            </>
          )}

          {tab === "about" && <About />}
        </div>
      </div>
    </>
  );
}
