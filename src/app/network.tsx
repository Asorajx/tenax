import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { invoke } from "@tauri-apps/api/core";

/* =========================
   Network Access
   ========================= */

/* The global switch for connected analysis. It is off every time Tenax starts. The Rust side holds */
/* the real switch and refuses connected commands while it is off, so this only mirrors it. */
interface NetworkAccess {
  enabled: boolean;
  setEnabled: (enabled: boolean) => void;
}

const NetworkContext = createContext<NetworkAccess>({ enabled: false, setEnabled: () => {} });

export function NetworkProvider({ children }: { children: ReactNode }) {
  const [enabled, setState] = useState(false);

  /* If the window is reloaded while the app keeps running, show what the backend really has. */
  useEffect(() => {
    invoke<boolean>("network_access")
      .then(setState)
      .catch(() => {});
  }, []);

  /* The switch only moves once the backend has confirmed it, so the two can never disagree. */
  const setEnabled = useCallback((next: boolean) => {
    invoke("set_network_access", { enabled: next })
      .then(() => setState(next))
      .catch(() => {});
  }, []);

  return <NetworkContext.Provider value={{ enabled, setEnabled }}>{children}</NetworkContext.Provider>;
}

export function useNetwork() {
  return useContext(NetworkContext);
}
