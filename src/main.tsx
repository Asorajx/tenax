import React from "react";
import ReactDOM from "react-dom/client";
import "@fontsource-variable/inter";
import "./styles/tokens.css";
import "./styles/base.css";
import "./styles/shell.css";
import "./styles/components.css";
import "./styles/floating.css";
import App from "./App";
import Splash from "./components/Splash";
import { DeviceCheckProvider } from "./app/deviceCheck";
import { NetworkProvider } from "./app/network";
import { RecentProvider } from "./app/recent";
import { applyTheme, loadTheme } from "./app/theme";

/* Apply the saved theme before the first render to avoid a flash. */
applyTheme(loadTheme());

/* The footer and layout settings no longer exist, so their saved values are removed. */
try {
  localStorage.removeItem("tenax.footer");
  localStorage.removeItem("tenax.layout");
} catch {
  /* Storage can be blocked, and there is nothing to clean up then. */
}

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <NetworkProvider>
      <RecentProvider>
        <DeviceCheckProvider>
          <App />
          <Splash />
        </DeviceCheckProvider>
      </RecentProvider>
    </NetworkProvider>
  </React.StrictMode>,
);
