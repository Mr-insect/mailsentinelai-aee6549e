import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Fingerprint,
  Globe2,
  Link2,
  Mails,
  Search,
  Server,
  ShieldAlert,
  Trash2,
  Upload,
} from "lucide-react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Panel, PageHeader } from "@/components/soc/Panel";
import { DemoTag, SeverityPill } from "@/components/soc/Pill";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useInvestigation } from "@/state/investigation-store";
import type { AnalysisResult, Severity } from "@/lib/types";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "SOC Dashboard — MailSentinel AI" },
      {
        name: "description",
        content:
          "Security operations dashboard showing analyzed emails, detected threats, suspicious URLs and IPs, and recent email investigations.",
      },
      { property: "og:title", content: "SOC Dashboard — MailSentinel AI" },
      {
        property: "og:description",
        content: "Live overview of email threats, IOC volume and recent forensic investigations.",
      },
    ],
  }),
  component: Dashboard,
});

const QUICK_START = [
  { step: "STEP 1", label: "Upload an .EML" },
  { step: "STEP 2", label: "Run AI Analysis" },
  { step: "STEP 3", label: "Investigate Threat" },
  { step: "STEP 4", label: "View Geolocation" },
  { step: "STEP 5", label: "Explore IOCs" },
  { step: "STEP 6", label: "Generate Report" },
];

const SEVERITY_FILTERS: ("ALL" | Severity)[] = [
  "ALL",
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "SAFE",
];

const DIST_COLORS: Record<string, string> = {
  Phishing: "var(--critical)",
  Malware: "var(--warning)",
  Spam: "var(--info)",
  Safe: "var(--safe)",
  Suspicious: "var(--chart-4)",
};

interface DashStats {
  total: number;
  malicious: number;
  suspicious: number;
  benign: number;
  critical: number;
  high: number;
  uniqueIocCount: number;
  aiCompleted: number;
  providerFailures: number;
  providerHitRate: number;
  topCountries: { name: string; count: number }[];
  topAsns: { name: string; count: number }[];
  topMaliciousDomains: { name: string; count: number }[];
  topMaliciousIps: { name: string; count: number }[];
  distribution: { name: string; value: number; color: string }[];
  activity: { day: string; threats: number; critical: number }[];
}

function deriveStats(history: AnalysisResult[]): DashStats {
  const malicious = history.filter((r) => r.severity === "HIGH" || r.severity === "CRITICAL").length;
  const suspicious = history.filter((r) => r.severity === "MEDIUM").length;
  const benign = history.filter((r) => r.severity === "SAFE" || r.severity === "LOW").length;
  const critical = history.filter((r) => r.severity === "CRITICAL").length;
  const high = history.filter((r) => r.severity === "HIGH").length;
  const uniqueIocs = new Set<string>();
  for (const r of history) for (const i of r.iocs ?? []) uniqueIocs.add(i.value);
  const aiCompleted = history.filter((r) => r.aiAssessment?.used).length;

  let failures = 0;
  for (const r of history) {
    for (const p of Object.values(r.providerHealth ?? {})) {
      if (p.configured && !["CONNECTED", "DISABLED"].includes(p.status)) failures += 1;
    }
  }
  const intelHits = history.filter(
    (r) =>
      (r.urlAnalysis ?? []).some((u) => u.reputation !== "UNKNOWN") ||
      (r.ipAnalysis ?? []).some((p) => p.reputation !== "UNKNOWN"),
  ).length;
  const providerHitRate = history.length ? Math.round((intelHits / history.length) * 100) : 0;

  const countryMap = new Map<string, number>();
  const asnMap = new Map<string, number>();
  const domMap = new Map<string, number>();
  const ipMap = new Map<string, number>();
  for (const r of history) {
    for (const d of r.ipAnalysis ?? []) {
      if (d.country && d.country !== "UNKNOWN") countryMap.set(d.country, (countryMap.get(d.country) ?? 0) + 1);
      if (d.asn && d.asn !== "UNKNOWN") asnMap.set(d.asn, (asnMap.get(d.asn) ?? 0) + 1);
      if (d.reputation === "MALICIOUS" || d.reputation === "SUSPICIOUS") ipMap.set(d.ip, (ipMap.get(d.ip) ?? 0) + 1);
    }
    for (const d of r.domainAnalysis ?? []) if (d.reputation === "MALICIOUS") domMap.set(d.domain, (domMap.get(d.domain) ?? 0) + 1);
  }
  const top = (m: Map<string, number>, n = 5) =>
    [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n).map(([name, ct]) => ({ name, count: ct }));

  const distribution = new Map<string, number>();
  for (const r of history) {
    const label =
      r.severity === "SAFE" || r.severity === "LOW" ? "Safe" : r.threatType in DIST_COLORS ? r.threatType : "Suspicious";
    distribution.set(label, (distribution.get(label) ?? 0) + 1);
  }
  const dist = [...distribution.entries()].map(([name, value]) => ({ name, value, color: DIST_COLORS[name] ?? "var(--chart-4)" }));

  // 7-day activity histogram from analyzedAt
  const days: { day: string; threats: number; critical: number }[] = [];
  const now = new Date();
  for (let i = 6; i >= 0; i--) {
    const d = new Date(now.getFullYear(), now.getMonth(), now.getDate() - i);
    days.push({
      day: d.toLocaleDateString(undefined, { weekday: "short" }),
      threats: 0,
      critical: 0,
    });
  }
  for (const r of history) {
    const t = new Date(r.analyzedAt).getTime();
    const idx = Math.floor((t - new Date(now.getFullYear(), now.getMonth(), now.getDate() - 6).getTime()) / 86400000);
    if (idx >= 0 && idx < 7) {
      days[idx].threats += r.severity === "MEDIUM" || r.severity === "HIGH" || r.severity === "CRITICAL" ? 1 : 0;
      if (r.severity === "CRITICAL") days[idx].critical += 1;
    }
  }

  return {
    total: history.length,
    malicious,
    suspicious,
    benign,
    critical,
    high,
    uniqueIocCount: uniqueIocs.size,
    aiCompleted,
    providerFailures: failures,
    providerHitRate,
    topCountries: top(countryMap),
    topAsns: top(asnMap),
    topMaliciousDomains: top(domMap),
    topMaliciousIps: top(ipMap),
    distribution: dist,
    activity: days,
  };
}

function locationOf(r: AnalysisResult): string {
  const g = r.geolocation ?? r.ipAnalysis?.[0];
  return g && g.city && g.country ? `${g.city}, ${g.country}` : "—";
}

function Dashboard() {
  const navigate = useNavigate();
  const { current, history, selectInvestigation, removeInvestigation } = useInvestigation();
  const [query, setQuery] = useState("");
  const [sev, setSev] = useState<(typeof SEVERITY_FILTERS)[number]>("ALL");
  const s = useMemo(() => deriveStats(history), [history]);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return [...history]
      .filter((r) => sev === "ALL" || r.severity === sev)
      .filter(
        (r) =>
          !q ||
          [r.email.from, r.threatType, r.investigationId].some((v) => v.toLowerCase().includes(q)) ||
          (r.iocs ?? []).some((i) => i.value.toLowerCase().includes(q)),
      )
      .sort((a, b) => new Date(b.analyzedAt).getTime() - new Date(a.analyzedAt).getTime())
      .slice(0, 15);
  }, [history, query, sev]);

  const open = (r: AnalysisResult) => {
    selectInvestigation(r.investigationId);
    navigate({ to: "/analyzer" });
  };

  const STAT_CARDS = [
    { label: "Emails Analyzed", value: s.total, icon: Mails, tone: "text-primary" },
    { label: "Malicious", value: s.malicious, icon: ShieldAlert, tone: "text-critical" },
    { label: "Suspicious", value: s.suspicious, icon: AlertTriangle, tone: "text-warning" },
    { label: "Benign", value: s.benign, icon: Server, tone: "text-safe" },
    { label: "Critical", value: s.critical, icon: Fingerprint, tone: "text-critical" },
    { label: "Unique IOCs", value: s.uniqueIocCount, icon: Link2, tone: "text-primary" },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Operations Dashboard"
        description="Upload a suspicious email → analyze → understand the threat → investigate its origin → extract evidence → generate a report."
        action={
          <div className="flex flex-wrap items-center gap-3">
            <DemoTag />
            <Button asChild>
              <Link to="/analyzer">
                <Upload className="size-4" /> Analyze an Email
              </Link>
            </Button>
          </div>
        }
      />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-6">
        {STAT_CARDS.map((card) => {
          const Icon = card.icon;
          return (
            <div key={card.label} className="glass animate-rise rounded-xl p-4">
              <div className="flex items-center justify-between">
                <span className="text-[11px] tracking-[0.14em] text-muted-foreground uppercase">{card.label}</span>
                <Icon className={`size-4 ${card.tone}`} />
              </div>
              <p className="mt-3 font-mono text-3xl font-semibold tabular-nums">{card.value}</p>
              <div className="mt-3 h-1 w-full overflow-hidden rounded-full bg-muted">
                <div className={`h-full w-2/3 rounded-full bg-current ${card.tone}`} />
              </div>
            </div>
          );
        })}
      </div>

      <Panel
        title="SOC Metrics"
        subtitle="Derived entirely from stored investigation results"
        icon={<Activity className="size-4" />}
      >
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Metric label="High-severity" value={s.high} />
          <Metric label="AI analyses completed" value={s.aiCompleted} />
          <Metric label="Provider hit rate" value={`${s.providerHitRate}%`} />
          <Metric label="Provider failures" value={s.providerFailures} />
        </div>
        <div className="mt-4 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <TopList title="Top Countries" rows={s.topCountries} />
          <TopList title="Top ASNs" rows={s.topAsns} />
          <TopList title="Malicious Domains" rows={s.topMaliciousDomains} />
          <TopList title="Malicious IPs" rows={s.topMaliciousIps} />
        </div>
      </Panel>

      <div className="grid gap-6 xl:grid-cols-3">
        <Panel title="Threat Distribution" subtitle="Classification of analyzed messages" icon={<ShieldAlert className="size-4" />}>
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={s.distribution} dataKey="value" nameKey="name" innerRadius={60} outerRadius={95} paddingAngle={3} stroke="none">
                  {s.distribution.map((d) => (
                    <Cell key={d.name} fill={d.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: "var(--popover)",
                    border: "1px solid var(--border)",
                    borderRadius: 12,
                    color: "var(--foreground)",
                  }}
                />
                <Legend wrapperStyle={{ fontSize: 12 }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </Panel>

        <Panel
          className="xl:col-span-2"
          title="Threat Activity"
          subtitle="Suspicious email volume over the last 7 days"
          icon={<Activity className="size-4" />}
        >
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={s.activity}>
                <defs>
                  <linearGradient id="gThreats" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="var(--info)" stopOpacity={0.55} />
                    <stop offset="100%" stopColor="var(--info)" stopOpacity={0.02} />
                  </linearGradient>
                  <linearGradient id="gCritical" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="var(--critical)" stopOpacity={0.55} />
                    <stop offset="100%" stopColor="var(--critical)" stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                <XAxis dataKey="day" stroke="var(--muted-foreground)" fontSize={12} tickLine={false} axisLine={false} />
                <YAxis stroke="var(--muted-foreground)" fontSize={12} tickLine={false} axisLine={false} />
                <Tooltip
                  contentStyle={{
                    background: "var(--popover)",
                    border: "1px solid var(--border)",
                    borderRadius: 12,
                    color: "var(--foreground)",
                  }}
                />
                <Area type="monotone" dataKey="threats" stroke="var(--info)" fill="url(#gThreats)" strokeWidth={2} name="Threats" />
                <Area type="monotone" dataKey="critical" stroke="var(--critical)" fill="url(#gCritical)" strokeWidth={2} name="Critical" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Panel>
      </div>

      <Panel
        title="Recent Investigations"
        subtitle="Click a row to open the investigation"
        icon={<Fingerprint className="size-4" />}
        bodyClassName="p-0"
      >
        <div className="flex flex-wrap items-center gap-3 border-b border-border/60 px-5 py-4">
          <div className="relative min-w-[220px] flex-1">
            <Search className="absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search sender, threat, IOC…"
              className="bg-background/60 pl-9"
            />
          </div>
          <div className="flex flex-wrap gap-2">
            {SEVERITY_FILTERS.map((f) => (
              <button
                key={f}
                onClick={() => setSev(f)}
                className={`rounded-full border px-3 py-1 text-xs transition-colors ${
                  sev === f ? "border-primary/50 bg-primary/15 text-primary" : "border-border/60 text-muted-foreground hover:text-foreground"
                }`}
              >
                {f === "ALL" ? "All" : f}
              </button>
            ))}
          </div>
          {history.length > 0 && (
            <Button size="sm" variant="outline" onClick={() => history[0] && removeInvestigation(history[0].investigationId)}>
              <Trash2 className="size-3.5" /> Delete Latest
            </Button>
          )}
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border/60 text-left text-[11px] tracking-[0.12em] text-muted-foreground uppercase">
                <th className="px-5 py-3 font-medium">Investigation</th>
                <th className="px-5 py-3 font-medium">Threat Type</th>
                <th className="px-5 py-3 font-medium">Risk</th>
                <th className="px-5 py-3 font-medium">Severity</th>
                <th className="px-5 py-3 font-medium">Location</th>
                <th className="px-5 py-3 font-medium">Mode</th>
                <th className="px-5 py-3 font-medium">Time</th>
                <th className="px-5 py-3 font-medium">Action</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr
                  key={r.investigationId}
                  onClick={() => open(r)}
                  className="cursor-pointer border-b border-border/40 transition-colors last:border-0 hover:bg-primary/5"
                >
                  <td className="px-5 py-3">
                    <p className="font-mono text-[11px] text-primary">{r.investigationId}</p>
                    <p className="max-w-[220px] truncate font-mono text-xs">{r.email.from}</p>
                  </td>
                  <td className="max-w-[180px] truncate px-5 py-3">{r.threatType}</td>
                  <td className="px-5 py-3 font-mono tabular-nums">{r.riskScore}</td>
                  <td className="px-5 py-3">
                    <SeverityPill value={r.severity} />
                  </td>
                  <td className="px-5 py-3 text-muted-foreground">
                    <span className="inline-flex items-center gap-1.5">
                      <Globe2 className="size-3.5" /> {locationOf(r)}
                    </span>
                  </td>
                  <td className="px-5 py-3 text-xs text-muted-foreground">{r.mode}</td>
                  <td className="px-5 py-3 font-mono text-xs text-muted-foreground">
                    {new Date(r.analyzedAt).toLocaleString()}
                  </td>
                  <td className="px-5 py-3">
                    <button
                      aria-label="Delete investigation"
                      className="rounded-md p-1.5 text-muted-foreground transition-colors hover:text-critical"
                      onClick={(e) => {
                        e.stopPropagation();
                        removeInvestigation(r.investigationId);
                      }}
                    >
                      <Trash2 className="size-4" />
                    </button>
                  </td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={8} className="px-5 py-8 text-center text-sm text-muted-foreground">
                    {history.length === 0
                      ? "No investigations yet. Analyze an email to populate the SOC dashboard with real data."
                      : "No investigations match this filter."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Panel>

      <Panel title="Quick Start" subtitle="Six steps from a suspicious email to a forensic report">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
          {QUICK_START.map((q) => (
            <div key={q.step} className="rounded-lg border border-border/60 bg-muted/20 p-4">
              <p className="text-[10px] tracking-[0.16em] text-primary uppercase">{q.step}</p>
              <p className="mt-1 text-sm font-medium">{q.label}</p>
            </div>
          ))}
        </div>
        {current && (
          <p className="mt-4 text-xs text-muted-foreground">
            Active investigation:{" "}
            <span className="font-mono text-foreground">{current.investigationId}</span> — {current.threatType}
          </p>
        )}
      </Panel>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="rounded-lg border border-border/60 bg-muted/15 p-4">
      <p className="text-[10px] tracking-[0.14em] text-muted-foreground uppercase">{label}</p>
      <p className="mt-1 font-mono text-2xl font-semibold tabular-nums">{value}</p>
    </div>
  );
}

function TopList({ title, rows }: { title: string; rows: { name: string; count: number }[] }) {
  return (
    <div className="rounded-lg border border-border/60 bg-background/40 p-4">
      <p className="text-[10px] tracking-[0.14em] text-muted-foreground uppercase">{title}</p>
      {rows.length === 0 ? (
        <p className="mt-2 text-xs text-muted-foreground">No data recorded.</p>
      ) : (
        <ul className="mt-2 space-y-1.5">
          {rows.map((r) => (
            <li key={r.name} className="flex items-center justify-between gap-3">
              <span className="truncate font-mono text-xs">{r.name}</span>
              <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px] tabular-nums">{r.count}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
