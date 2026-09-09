import type { Reputation, Severity } from "@/lib/types";

export const severityClasses: Record<Severity, string> = {
  SAFE: "text-safe border-safe/40 bg-safe/10",
  LOW: "text-safe border-safe/40 bg-safe/10",
  MEDIUM: "text-warning border-warning/40 bg-warning/10",
  HIGH: "text-warning border-warning/50 bg-warning/15",
  CRITICAL: "text-critical border-critical/50 bg-critical/15",
};

export const severityHex: Record<Severity, string> = {
  SAFE: "var(--safe)",
  LOW: "var(--safe)",
  MEDIUM: "var(--warning)",
  HIGH: "var(--warning)",
  CRITICAL: "var(--critical)",
};

export const reputationClasses: Record<Reputation, string> = {
  CLEAN: "text-safe border-safe/40 bg-safe/10",
  SUSPICIOUS: "text-warning border-warning/40 bg-warning/10",
  MALICIOUS: "text-critical border-critical/50 bg-critical/15",
  UNKNOWN: "text-muted-foreground border-border bg-muted/40",
};

export const authClasses: Record<string, string> = {
  PASS: "text-safe border-safe/40 bg-safe/10",
  FAIL: "text-critical border-critical/50 bg-critical/15",
  SUSPICIOUS: "text-warning border-warning/40 bg-warning/10",
  UNKNOWN: "text-muted-foreground border-border bg-muted/40",
};
