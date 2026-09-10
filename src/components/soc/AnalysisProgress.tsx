import { Check, Loader2 } from "lucide-react";

export const ANALYSIS_STEPS = [
  "Parsing email",
  "Extracting headers",
  "Checking sender",
  "Analyzing SPF",
  "Analyzing DKIM",
  "Analyzing DMARC",
  "Extracting URLs",
  "Investigating IP addresses",
  "Checking domain reputation",
  "Extracting IOCs",
  "Performing forensic analysis",
  "Calculating threat score",
];

export function AnalysisProgress({ step }: { step: number }) {
  const done = step >= ANALYSIS_STEPS.length;
  return (
    <div className="glass grid-scan animate-rise relative overflow-hidden rounded-xl p-6">
      <div className="pointer-events-none absolute inset-x-0 top-0 h-24 animate-sweep bg-gradient-to-b from-primary/20 to-transparent" />
      <div className="relative">
        <p className="text-xs tracking-[0.18em] text-primary uppercase">
          {done ? "Analysis complete" : "Analysis in progress"}
        </p>
        <div className="mt-4 grid gap-2 sm:grid-cols-2">
          {ANALYSIS_STEPS.map((label, i) => {
            const complete = i < step;
            const active = i === step;
            return (
              <div
                key={label}
                className={`flex items-center gap-2.5 rounded-md border px-3 py-2 text-sm transition-colors ${
                  complete
                    ? "border-safe/30 bg-safe/8 text-foreground"
                    : active
                      ? "border-primary/40 bg-primary/10 text-primary"
                      : "border-border/40 bg-muted/10 text-muted-foreground/60"
                }`}
              >
                {complete ? (
                  <Check className="size-4 text-safe" />
                ) : active ? (
                  <Loader2 className="size-4 animate-spin" />
                ) : (
                  <span className="size-4 rounded-full border border-current opacity-40" />
                )}
                {label}
              </div>
            );
          })}
        </div>
        <div className="mt-5 h-1.5 w-full overflow-hidden rounded-full bg-muted">
          <div
            className="h-full rounded-full bg-primary transition-[width] duration-300"
            style={{ width: `${Math.min(100, (step / ANALYSIS_STEPS.length) * 100)}%` }}
          />
        </div>
      </div>
    </div>
  );
}
