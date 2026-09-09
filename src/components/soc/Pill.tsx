import { cn } from "@/lib/utils";
import type { Reputation, Severity } from "@/lib/types";
import { authClasses, reputationClasses, severityClasses } from "./severity";

export function SeverityPill({ value, className }: { value: Severity; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-semibold tracking-wider uppercase",
        severityClasses[value],
        className,
      )}
    >
      <span className="size-1.5 rounded-full bg-current" />
      {value}
    </span>
  );
}

export function ReputationPill({ value }: { value: Reputation }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border px-2.5 py-0.5 text-[11px] font-semibold tracking-wider uppercase",
        reputationClasses[value],
      )}
    >
      {value}
    </span>
  );
}

export function AuthPill({ value }: { value: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border px-2.5 py-0.5 text-[11px] font-semibold tracking-wider uppercase",
        authClasses[value] ?? authClasses["UNKNOWN"],
      )}
    >
      {value}
    </span>
  );
}

export function DemoTag({ label = "Demo Intelligence" }: { label?: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border border-primary/30 bg-primary/10 px-2.5 py-0.5 text-[10px] font-semibold tracking-[0.14em] text-primary uppercase">
      <span className="size-1.5 animate-pulse-dot rounded-full bg-primary" />
      {label}
    </span>
  );
}
