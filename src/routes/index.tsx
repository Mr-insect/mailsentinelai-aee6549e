import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import {
  Activity,
  AlertTriangle,
  Fingerprint,
  Globe2,
  Link2,
  Mails,
  Server,
  ShieldAlert,
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
import { useInvestigation } from "@/state/investigation-store";
import type { Severity } from "@/lib/types";

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

const STATS = [
  { label: "Emails Analyzed", value: "1,284", icon: Mails, tone: "text-primary" },
  { label: "Threats Detected", value: "327", icon: ShieldAlert, tone: "text-warning" },
  { label: "Critical Threats", value: "86", icon: AlertTriangle, tone: "text-critical" },
  { label: "Suspicious URLs", value: "142", icon: Link2, tone: "text-warning" },
  { label: "Suspicious IPs", value: "73", icon: Server, tone: "text-warning" },
  { label: "IOCs Extracted", value: "418", icon: Fingerprint, tone: "text-primary" },
];

const DISTRIBUTION = [
  { name: "Phishing", value: 148, color: "var(--critical)" },
  { name: "Malware", value: 72, color: "var(--warning)" },
  { name: "Credential Theft", value: 61, color: "var(--chart-4)" },
  { name: "Spam", value: 46, color: "var(--info)" },
  { name: "Safe", value: 957, color: "var(--safe)" },
];

const ACTIVITY = [
  { day: "Mon", threats: 34, critical: 8 },
  { day: "Tue", threats: 48, critical: 12 },
  { day: "Wed", threats: 41, critical: 9 },
  { day: "Thu", threats: 66, critical: 19 },
  { day: "Fri", threats: 59, critical: 14 },
  { day: "Sat", threats: 27, critical: 6 },
  { day: "Sun", threats: 52, critical: 18 },
];

const RECENT: {
  email: string;
  threat: string;
  score: number;
  severity: Severity;
  location: string;
  status: string;
  time: string;
  demo: "phishing" | "malware" | "safe";
}[] = [
  {
    email: "it-helpdesk@university-secure-verify.top",
    threat: "Credential Phishing",
    score: 93,
    severity: "CRITICAL",
    location: "Amsterdam, NL",
    status: "Quarantined",
    time: "10:42",
    demo: "phishing",
  },
  {
    email: "accounts@invoice-billing-dept.click",
    threat: "Malware Delivery",
    score: 89,
    severity: "CRITICAL",
    location: "Saint Petersburg, RU",
    status: "Quarantined",
    time: "09:14",
    demo: "malware",
  },
  {
    email: "no-reply@offers-rewards.xyz",
    threat: "Spam / Suspicious Link",
    score: 47,
    severity: "MEDIUM",
    location: "Lagos, NG",
    status: "Flagged",
    time: "08:51",
    demo: "phishing",
  },
  {
    email: "events@univ.edu",
    threat: "No Threat Detected",
    score: 4,
    severity: "SAFE",
    location: "Mumbai, IN",
    status: "Delivered",
    time: "07:28",
    demo: "safe",
  },
];

const QUICK_START = [
  { step: "STEP 1", label: "Upload an .EML" },
  { step: "STEP 2", label: "Run AI Analysis" },
  { step: "STEP 3", label: "Investigate Threat" },
  { step: "STEP 4", label: "View Geolocation" },
  { step: "STEP 5", label: "Explore IOCs" },
  { step: "STEP 6", label: "Generate Report" },
];

function Dashboard() {
  const navigate = useNavigate();
  const { current } = useInvestigation();

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
        {STATS.map((s) => {
          const Icon = s.icon;
          return (
            <div key={s.label} className="glass animate-rise rounded-xl p-4">
              <div className="flex items-center justify-between">
                <span className="text-[11px] tracking-[0.14em] text-muted-foreground uppercase">{s.label}</span>
                <Icon className={`size-4 ${s.tone}`} />
              </div>
              <p className="mt-3 font-mono text-3xl font-semibold tabular-nums">{s.value}</p>
              <div className="mt-3 h-1 w-full overflow-hidden rounded-full bg-muted">
                <div className={`h-full w-2/3 rounded-full bg-current ${s.tone}`} />
              </div>
            </div>
          );
        })}
      </div>

      <div className="grid gap-6 xl:grid-cols-3">
        <Panel title="Threat Distribution" subtitle="Classification of analyzed messages" icon={<ShieldAlert className="size-4" />}>
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={DISTRIBUTION} dataKey="value" nameKey="name" innerRadius={60} outerRadius={95} paddingAngle={3} stroke="none">
                  {DISTRIBUTION.map((d) => (
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
              <AreaChart data={ACTIVITY}>
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
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border/60 text-left text-[11px] tracking-[0.12em] text-muted-foreground uppercase">
                <th className="px-5 py-3 font-medium">Email</th>
                <th className="px-5 py-3 font-medium">Threat Type</th>
                <th className="px-5 py-3 font-medium">Risk</th>
                <th className="px-5 py-3 font-medium">Severity</th>
                <th className="px-5 py-3 font-medium">Location</th>
                <th className="px-5 py-3 font-medium">Status</th>
                <th className="px-5 py-3 font-medium">Time</th>
              </tr>
            </thead>
            <tbody>
              {RECENT.map((r) => (
                <tr
                  key={r.email}
                  onClick={() => navigate({ to: "/analyzer", search: { demo: r.demo } })}
                  className="cursor-pointer border-b border-border/40 transition-colors last:border-0 hover:bg-primary/5"
                >
                  <td className="px-5 py-3 font-mono text-xs">{r.email}</td>
                  <td className="px-5 py-3">{r.threat}</td>
                  <td className="px-5 py-3 font-mono tabular-nums">{r.score}</td>
                  <td className="px-5 py-3">
                    <SeverityPill value={r.severity} />
                  </td>
                  <td className="px-5 py-3 text-muted-foreground">
                    <span className="inline-flex items-center gap-1.5">
                      <Globe2 className="size-3.5" /> {r.location}
                    </span>
                  </td>
                  <td className="px-5 py-3 text-muted-foreground">{r.status}</td>
                  <td className="px-5 py-3 font-mono text-xs text-muted-foreground">{r.time}</td>
                </tr>
              ))}
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
