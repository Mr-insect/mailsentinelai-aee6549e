import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import type { AnalysisResult } from "@/lib/types";

/**
 * Investigation history persists locally (localStorage MVP).
 * Raw email bodies are NOT stored by default — analysis metadata only.
 */
const STORAGE_KEY = "mailsentinel.history.v1";
const MAX_HISTORY = 50;

/** Strip raw message bodies before persisting (privacy by default). */
function sanitizeForStorage(r: AnalysisResult): AnalysisResult {
  return {
    ...r,
    email: { ...r.email, body: "", textBody: "", htmlBody: "", rawHeaders: "" },
  };
}

function loadHistory(): AnalysisResult[] {
  try {
    if (typeof localStorage === "undefined") return [];
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const arr: unknown = JSON.parse(raw);
    if (!Array.isArray(arr)) return [];
    return arr.filter(
      (x): x is AnalysisResult =>
        !!x && typeof x === "object" && typeof (x as AnalysisResult).investigationId === "string",
    );
  } catch {
    return [];
  }
}

interface InvestigationState {
  current: AnalysisResult | null;
  history: AnalysisResult[];
  setResult: (result: AnalysisResult) => void;
  selectInvestigation: (id: string) => void;
  removeInvestigation: (id: string) => void;
  clear: () => void;
}

const Ctx = createContext<InvestigationState | null>(null);

export function InvestigationProvider({ children }: { children: ReactNode }) {
  const [current, setCurrent] = useState<AnalysisResult | null>(null);
  const [history, setHistory] = useState<AnalysisResult[]>(loadHistory);

  // Persist metadata (bodies stripped) whenever history changes.
  useEffect(() => {
    try {
      if (typeof localStorage === "undefined") return;
      localStorage.setItem(STORAGE_KEY, JSON.stringify(history.map(sanitizeForStorage)));
    } catch {
      // storage full/unavailable — history stays in-memory only
    }
  }, [history]);

  const setResult = useCallback((result: AnalysisResult) => {
    setCurrent(result);
    setHistory((prev) => [result, ...prev.filter((r) => r.investigationId !== result.investigationId)].slice(0, MAX_HISTORY));
  }, []);

  const selectInvestigation = useCallback((id: string) => {
    setHistory((prev) => {
      const found = prev.find((r) => r.investigationId === id);
      if (found) setCurrent(found);
      return prev;
    });
  }, []);

  const removeInvestigation = useCallback((id: string) => {
    setHistory((prev) => {
      const next = prev.filter((r) => r.investigationId !== id);
      setCurrent((c) => (c?.investigationId === id ? null : c));
      return next;
    });
  }, []);

  const clear = useCallback(() => {
    setCurrent(null);
    setHistory([]);
    try {
      if (typeof localStorage !== "undefined") localStorage.removeItem(STORAGE_KEY);
    } catch {
      // ignore
    }
  }, []);

  const value = useMemo(
    () => ({ current, history, setResult, selectInvestigation, removeInvestigation, clear }),
    [current, history, setResult, selectInvestigation, removeInvestigation, clear],
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useInvestigation(): InvestigationState {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useInvestigation must be used inside InvestigationProvider");
  return ctx;
}
