import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { Finding } from "../components/Finding";
import { deviceStatus } from "../components/floating/DeviceRing";
import { useRecent } from "./recent";

/* =========================
   Device Check
   ========================= */

/* The Windows Security check, run once and shared. The Windows Security page and the Home screen both */
/* read this, so opening one after the other never reads the settings again. The check only reads */
/* settings on this PC, so it is quick and sends nothing anywhere. Nothing is saved: the result lives in */
/* memory until the app is closed. It only runs when someone asks for it. */
export type DevicePhase = "idle" | "loading" | "done" | "error";

interface DeviceCheck {
  phase: DevicePhase;
  findings: Finding[];
  seconds: number;
  /* When the settings were last read, or null if they have not been. */
  checkedAt: Date | null;
  error: string;
  /* Reads the settings now. A check that is already running is not started twice. */
  run: () => Promise<void>;
}

const DeviceCheckContext = createContext<DeviceCheck>({
  phase: "idle",
  findings: [],
  seconds: 0,
  checkedAt: null,
  error: "",
  run: async () => {},
});

export function DeviceCheckProvider({ children }: { children: ReactNode }) {
  const [phase, setPhase] = useState<DevicePhase>("idle");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [seconds, setSeconds] = useState(0);
  const [checkedAt, setCheckedAt] = useState<Date | null>(null);
  const [error, setError] = useState("");
  const running = useRef(false);
  const { record } = useRecent();

  /* Asks the Rust backend to read the settings, then keeps what it returns. */
  const run = useCallback(async () => {
    if (running.current) return;
    running.current = true;
    setPhase("loading");
    const started = performance.now();
    try {
      const result = await invoke<Finding[]>("check_windows_security");
      setFindings(result);
      setSeconds((performance.now() - started) / 1000);
      setCheckedAt(new Date());
      setPhase("done");
      const summary = deviceStatus(result);
      record({ title: "Windows Security", headline: summary.title, status: summary.status });
    } catch (reason) {
      setError(String(reason));
      setPhase("error");
    } finally {
      running.current = false;
    }
  }, [record]);

  return (
    <DeviceCheckContext.Provider value={{ phase, findings, seconds, checkedAt, error, run }}>
      {children}
    </DeviceCheckContext.Provider>
  );
}

export function useDeviceCheck() {
  return useContext(DeviceCheckContext);
}
