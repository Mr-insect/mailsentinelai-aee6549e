import { useEffect, useState } from "react";
import type { Severity } from "@/lib/types";
import { severityHex } from "./severity";

export function RiskGauge({ score, severity, size = 208 }: { score: number; severity: Severity; size?: number }) {
  const [shown, setShown] = useState(0);

  useEffect(() => {
    setShown(0);
    const start = performance.now();
    const duration = 1100;
    let frame = 0;
    const tick = (now: number) => {
      const p = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - p, 3);
      setShown(Math.round(score * eased));
      if (p < 1) frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [score]);

  const stroke = 14;
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const color = severityHex[severity];

  return (
    <div className="relative grid place-items-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--muted)" strokeWidth={stroke} />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={c - (c * shown) / 100}
          style={{ filter: `drop-shadow(0 0 10px ${color})`, transition: "stroke 0.4s ease" }}
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className="font-mono text-5xl font-bold tabular-nums" style={{ color }}>
          {shown}
        </span>
        <span className="text-xs tracking-[0.2em] text-muted-foreground uppercase">/ 100 risk</span>
      </div>
    </div>
  );
}
