import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";
import type { AnalysisResult } from "@/lib/types";

interface InvestigationState {
  current: AnalysisResult | null;
  history: AnalysisResult[];
  setResult: (result: AnalysisResult) => void;
  selectInvestigation: (id: string) => void;
  clear: () => void;
}

const Ctx = createContext<InvestigationState | null>(null);

export function InvestigationProvider({ children }: { children: ReactNode }) {
  const [current, setCurrent] = useState<AnalysisResult | null>(null);
  const [history, setHistory] = useState<AnalysisResult[]>([]);

  const setResult = useCallback((result: AnalysisResult) => {
    setCurrent(result);
    setHistory((prev) => [result, ...prev.filter((r) => r.investigationId !== result.investigationId)].slice(0, 25));
  }, []);

  const selectInvestigation = useCallback((id: string) => {
    setHistory((prev) => {
      const found = prev.find((r) => r.investigationId === id);
      if (found) setCurrent(found);
      return prev;
    });
  }, []);

  const clear = useCallback(() => setCurrent(null), []);

  const value = useMemo(
    () => ({ current, history, setResult, selectInvestigation, clear }),
    [current, history, setResult, selectInvestigation, clear],
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useInvestigation(): InvestigationState {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useInvestigation must be used inside InvestigationProvider");
  return ctx;
}
