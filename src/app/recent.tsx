import { createContext, useCallback, useContext, useState, type ReactNode } from "react";
import type { FindingStatus } from "../components/Finding";

/* =========================
   Recent Results
   ========================= */

/* The latest result from each tool, for the Home screen. It keeps only the tool's name, the one-line */
/* result and when it was read, never what was typed in. It lives in memory until the app is closed. */
export interface RecentResult {
  title: string;
  headline?: string;
  status: FindingStatus;
  at: Date;
}

/* The most results kept. */
const LIMIT = 5;

interface Recent {
  results: RecentResult[];
  record: (result: Omit<RecentResult, "at">) => void;
}

const RecentContext = createContext<Recent>({ results: [], record: () => {} });

export function RecentProvider({ children }: { children: ReactNode }) {
  const [results, setResults] = useState<RecentResult[]>([]);

  /* A tool is listed once, with its newest result at the top. */
  const record = useCallback((result: Omit<RecentResult, "at">) => {
    setResults((known) => [{ ...result, at: new Date() }, ...known.filter((item) => item.title !== result.title)].slice(0, LIMIT));
  }, []);

  return <RecentContext.Provider value={{ results, record }}>{children}</RecentContext.Provider>;
}

export function useRecent() {
  return useContext(RecentContext);
}

/* The most serious status among some findings, used as the colour of a recent result. */
const SEVERITY: FindingStatus[] = ["ok", "info", "unknown", "limited", "warning", "risk"];

export function worstStatus(statuses: FindingStatus[]): FindingStatus {
  return statuses.reduce((worst, status) => (SEVERITY.indexOf(status) > SEVERITY.indexOf(worst) ? status : worst), "ok");
}
