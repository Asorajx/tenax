import type { Theme } from "../app/theme";

/* =========================
   Settings
   ========================= */

const THEMES: { value: Theme; label: string }[] = [
  { value: "dark", label: "Dark" },
  { value: "light", label: "Light" },
  { value: "system", label: "System" },
];

const SHORTCUTS = [
  { keys: "Ctrl + 1", action: "Home" },
  { keys: "Ctrl + 2 to 5", action: "First tool in each group" },
  { keys: "Ctrl + ,", action: "Settings" },
  { keys: "Ctrl + Shift + L", action: "Switch between light and dark" },
  { keys: "Up / Down", action: "Move through the sidebar" },
];

interface SettingsProps {
  theme: Theme;
  onThemeChange: (theme: Theme) => void;
}

export default function Settings({ theme, onThemeChange }: SettingsProps) {
  return (
    <>
      <header className="page-header">
        <h1>Settings</h1>
      </header>

      <section className="section">
        <h2>Appearance</h2>
        <div className="panel">
          <div className="row">
            <span className="row-text">
              <span className="row-title" id="theme-label">Theme</span>
              <span>System follows your Windows colour mode.</span>
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
        </div>
      </section>

      <section className="section">
        <h2>Keyboard shortcuts</h2>
        <div className="panel">
          {SHORTCUTS.map((shortcut) => (
            <div key={shortcut.keys} className="row">
              <span>{shortcut.action}</span>
              <kbd>{shortcut.keys}</kbd>
            </div>
          ))}
        </div>
      </section>
    </>
  );
}
