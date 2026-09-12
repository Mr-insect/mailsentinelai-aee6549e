import { useState } from "react";
import { Link } from "@tanstack/react-router";
import {
  AlarmClock,
  CornerUpLeft,
  FileWarning,
  Globe,
  Key,
  KeyRound,
  Link2,
  Paperclip,
  Scale,
  Server,
  Shield,
  ShieldCheck,
  Terminal,
  User,
  Copy,
  CheckCircle2,
  XCircle,
  HelpCircle,
} from "lucide-react";
import { toast } from "sonner";
import { Panel } from "./Panel";
import { AuthPill, DemoTag, ReputationPill, SeverityPill } from "./Pill";
import { RiskGauge } from "./RiskGauge";
import { Button } from "@/components/ui/button";
import { severityHex } from "./severity";
import type { AnalysisResult } from "@/lib/types";

const ICONS: Record<string, typeof Shield> = {
  shield: Shield,
  key: Key,
  scale: Scale,
  user: User,
  "corner-up-left": CornerUpLeft,
  "key-round": KeyRound,
  "alarm-clock": AlarmClock,
  link: Link2,
  globe: Globe,
  paperclip: Paperclip,
  server: Server,
};

export function AnalysisResults({ result }: { result: AnalysisResult }) {
  const [showRaw, setShowRaw] = useState(false);
  const color = severityHex[result.severity];

  const copy = (value: string) => {
    navigator.clipboard?.writeText(value).then(
      () => toast.success("Copied to clipboard"),
      () => toast.error("Clipboard is not available in this browser"),
    );
  };

  return (
    <div className="space-y-6">
      {/* VERDICT */}
      <section className="glass grid-scan animate-rise overflow-hidden rounded-xl">
        <div className="grid gap-6 p-6 lg:grid-cols-[auto_1fr] lg:items-center">
          <RiskGauge score={result.riskScore} severity={result.severity} />
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-3">
              <span
                className="rounded-lg border px-3 py-1 text-sm font-bold tracking-[0.18em] uppercase"
                style={{ color, borderColor: color, background: `color-mix(in oklch, ${color} 14%, transparent)` }}
              >
                {result.severity === "SAFE" || result.severity === "LOW" ? "No Threat Detected" : `${result.severity} Threat`}
              </span>
              <DemoTag label="AI-Assisted Demo Analysis" />
            </div>
            <div className="grid gap-4 sm:grid-cols-3">
              <Field label="Threat Type" value={result.threatType} />
              <Field label="Risk Score" value={`${result.riskScore} / 100`} />
              <Field label="Analysis Confidence" value={`${result.confidence}%`} />
              <Field label="Investigation ID" value={result.investigationId} mono />
              <Field label="Sender" value={result.email.from} mono />
              <Field label="Subject" value={result.email.subject} />
            </div>
            <div className="flex flex-wrap gap-2 pt-1">
              <Button asChild size="sm" variant="outline">
                <Link to="/geolocation">View Geolocation</Link>
              </Button>
              <Button asChild size="sm" variant="outline">
                <Link to="/forensics">Forensic Investigation</Link>
              </Button>
              <Button asChild size="sm" variant="outline">
                <Link to="/ioc">Explore IOCs</Link>
              </Button>
              <Button asChild size="sm">
                <Link to="/reports">Generate Report</Link>
              </Button>
            </div>
          </div>
        </div>
      </section>

      {/* WHY FLAGGED */}
      <Panel
        title="Why was this email flagged?"
        subtitle="Every rule that contributed to the score, with its explanation"
        icon={<ShieldCheck className="size-4" />}
      >
        <div className="grid gap-3 md:grid-cols-2">
          {result.indicators.map((ind) => {
            const Icon = ICONS[ind.icon] ?? Shield;
            const StatusIcon = ind.status === "DETECTED" ? XCircle : ind.status === "CLEAR" ? CheckCircle2 : HelpCircle;
            const tone =
              ind.status === "DETECTED" ? "text-critical" : ind.status === "CLEAR" ? "text-safe" : "text-muted-foreground";
            return (
              <div
                key={ind.id}
                className="flex gap-3 rounded-lg border border-border/60 bg-muted/15 p-4"
              >
                <span className={`mt-0.5 grid size-8 shrink-0 place-items-center rounded-md bg-background/60 ${tone}`}>
                  <Icon className="size-4" />
                </span>
                <div className="min-w-0">
                  <p className="flex flex-wrap items-center gap-2 text-sm font-medium">
                    {ind.name}
                    <span className={`inline-flex items-center gap-1 text-[11px] font-semibold uppercase ${tone}`}>
                      <StatusIcon className="size-3.5" />
                      {ind.status}
                    </span>
                    {ind.weight > 0 && (
                      <span className="rounded border border-critical/40 bg-critical/10 px-1.5 text-[10px] font-mono text-critical">
                        +{ind.weight}
                      </span>
                    )}
                  </p>
                  <p className="mt-1 text-xs break-words text-muted-foreground">{ind.explanation}</p>
                </div>
              </div>
            );
          })}
        </div>
      </Panel>

      {/* AUTH */}
      <Panel
        title="Email Authentication Analysis"
        subtitle="SPF, DKIM and DMARC verdicts read from the message headers"
        icon={<Shield className="size-4" />}
        action={<DemoTag />}
      >
        <div className="grid gap-4 md:grid-cols-3">
          {result.authenticationAnalysis.map((a) => (
            <div key={a.name} className="rounded-lg border border-border/60 bg-muted/15 p-5">
              <div className="flex items-center justify-between">
                <p className="text-lg font-semibold tracking-wide">{a.name}</p>
                <AuthPill value={a.status} />
              </div>
              <p className="mt-3 text-xs text-muted-foreground">{a.explanation}</p>
            </div>
          ))}
        </div>
      </Panel>

      {/* HEADERS */}
      <Panel
        title="Email Header Forensics"
        icon={<Terminal className="size-4" />}
        action={
          <Button size="sm" variant="outline" onClick={() => setShowRaw((v) => !v)}>
            {showRaw ? "Hide Raw Headers" : "View Raw Headers"}
          </Button>
        }
        bodyClassName="p-0"
      >
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border/60 text-left text-[11px] tracking-[0.12em] text-muted-foreground uppercase">
                <th className="px-5 py-3 font-medium">Header</th>
                <th className="px-5 py-3 font-medium">Value</th>
                <th className="px-5 py-3 font-medium">Analysis</th>
              </tr>
            </thead>
            <tbody className="font-mono text-xs">
              {headerRows(result).map((row) => (
                <tr key={row.name} className="border-b border-border/40 last:border-0">
                  <td className="px-5 py-3 whitespace-nowrap text-muted-foreground">{row.name}</td>
                  <td className="max-w-md px-5 py-3 break-all">{row.value || "UNKNOWN"}</td>
                  <td className="px-5 py-3">
                    <span
                      className={
                        row.verdict === "Suspicious"
                          ? "text-critical"
                          : row.verdict === "Clean"
                            ? "text-safe"
                            : "text-muted-foreground"
                      }
                    >
                      {row.verdict}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {showRaw && (
          <pre className="m-5 max-h-96 overflow-auto rounded-lg border border-border bg-background/80 p-4 font-mono text-[11px] leading-relaxed text-primary/90">
            {result.email.rawHeaders || "UNKNOWN"}
          </pre>
        )}
      </Panel>

      {/* SENDER */}
      <Panel title="Sender Intelligence" icon={<User className="size-4" />} action={<SeverityPill value={result.senderAnalysis.risk} />}>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Field label="Sender Email" value={result.senderAnalysis.email} mono />
          <Field label="Display Name" value={result.senderAnalysis.displayName} />
          <Field label="Sender Domain" value={result.senderAnalysis.domain} mono />
          <Field label="Reply-To" value={result.senderAnalysis.replyTo} mono />
          <Field label="Domain Age" value={result.senderAnalysis.domainAge} />
          <Field label="Domain Reputation" value={result.senderAnalysis.domainReputation} />
          <Field label="Authentication" value={result.senderAnalysis.authStatus} />
          <Field label="Risk Level" value={result.senderAnalysis.risk} />
        </div>
        {result.senderAnalysis.lookalike && (
          <p className="mt-4 rounded-lg border border-critical/40 bg-critical/10 px-4 py-3 text-sm text-critical">
            Domain resembles a legitimate organization
            {result.senderAnalysis.lookalikeOf ? ` ("${result.senderAnalysis.lookalikeOf}")` : ""} — classic impersonation pattern.
          </p>
        )}
        {result.senderAnalysis.replyToMismatch && (
          <p className="mt-3 rounded-lg border border-warning/40 bg-warning/10 px-4 py-3 text-sm text-warning">
            Reply-To points to a different domain than the sender — replies would leave your organisation.
          </p>
        )}
      </Panel>

      {/* URLS */}
      <Panel title="URL Analysis" icon={<Link2 className="size-4" />} bodyClassName={result.urlAnalysis.length ? "p-0" : "p-5"}>
        {result.urlAnalysis.length === 0 ? (
          <p className="text-sm text-muted-foreground">No URLs were found in this message.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border/60 text-left text-[11px] tracking-[0.12em] text-muted-foreground uppercase">
                  <th className="px-5 py-3 font-medium">URL</th>
                  <th className="px-5 py-3 font-medium">Domain</th>
                  <th className="px-5 py-3 font-medium">HTTPS</th>
                  <th className="px-5 py-3 font-medium">Redirect</th>
                  <th className="px-5 py-3 font-medium">Reputation</th>
                  <th className="px-5 py-3 font-medium">Risk</th>
                </tr>
              </thead>
              <tbody>
                {result.urlAnalysis.map((u) => (
                  <tr key={u.url} className="border-b border-border/40 align-top last:border-0">
                    <td className="max-w-sm px-5 py-3 font-mono text-xs break-all">
                      {u.url}
                      {u.notes.length > 0 && (
                        <ul className="mt-2 space-y-1 font-sans text-[11px] text-warning">
                          {u.notes.map((n) => (
                            <li key={n}>• {n}</li>
                          ))}
                        </ul>
                      )}
                    </td>
                    <td className="px-5 py-3 font-mono text-xs">{u.domain}</td>
                    <td className="px-5 py-3 text-xs">{u.https ? "Yes" : "No"}</td>
                    <td className="px-5 py-3 text-xs">{u.redirect ? "Yes" : "No"}</td>
                    <td className="px-5 py-3">
                      <ReputationPill value={u.reputation} />
                    </td>
                    <td className="px-5 py-3">
                      <SeverityPill value={u.risk} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {/* IPs */}
      <Panel title="IP Intelligence" icon={<Server className="size-4" />} action={<DemoTag />} bodyClassName={result.ipAnalysis.length ? "p-0" : "p-5"}>
        {result.ipAnalysis.length === 0 ? (
          <p className="text-sm text-muted-foreground">No public IP addresses were found in the Received chain.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border/60 text-left text-[11px] tracking-[0.12em] text-muted-foreground uppercase">
                  <th className="px-5 py-3 font-medium">IP Address</th>
                  <th className="px-5 py-3 font-medium">Reputation</th>
                  <th className="px-5 py-3 font-medium">Country</th>
                  <th className="px-5 py-3 font-medium">City</th>
                  <th className="px-5 py-3 font-medium">ISP</th>
                  <th className="px-5 py-3 font-medium">ASN</th>
                  <th className="px-5 py-3 font-medium">Risk</th>
                </tr>
              </thead>
              <tbody>
                {result.ipAnalysis.map((ip) => (
                  <tr key={ip.ip} className="border-b border-border/40 last:border-0">
                    <td className="px-5 py-3 font-mono text-xs">{ip.ip}</td>
                    <td className="px-5 py-3">
                      <ReputationPill value={ip.reputation} />
                    </td>
                    <td className="px-5 py-3 text-xs">{ip.country}</td>
                    <td className="px-5 py-3 text-xs">{ip.city}</td>
                    <td className="px-5 py-3 text-xs">{ip.isp}</td>
                    <td className="px-5 py-3 font-mono text-xs">{ip.asn}</td>
                    <td className="px-5 py-3">
                      <SeverityPill value={ip.risk} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {/* ATTACHMENTS */}
      <Panel title="Attachment Analysis" subtitle="Static inspection only — nothing is opened or executed" icon={<FileWarning className="size-4" />}>
        {result.attachments.length === 0 ? (
          <p className="text-sm text-muted-foreground">This email contains no attachments.</p>
        ) : (
          <div className="space-y-3">
            {result.attachments.map((a) => (
              <div key={a.filename} className="rounded-lg border border-border/60 bg-muted/15 p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <p className="font-mono text-sm">{a.filename}</p>
                  <SeverityPill value={a.risk} />
                </div>
                <div className="mt-3 grid gap-3 text-xs sm:grid-cols-4">
                  <Field label="File Type" value={a.contentType} small />
                  <Field label="Size" value={a.sizeLabel} small />
                  <Field label="Status" value={a.status} small />
                  <div className="min-w-0">
                    <p className="flex flex-wrap items-center gap-1.5 text-[10px] tracking-[0.14em] text-muted-foreground uppercase">
                      SHA-256
                      {a.sha256 && (
                        <span className="rounded border border-safe/40 bg-safe/10 px-1.5 py-0.5 text-[9px] tracking-[0.1em] text-safe normal-case">
                          Cryptographically computed
                        </span>
                      )}
                    </p>
                    {a.sha256 ? (
                      <button
                        onClick={() => copy(a.sha256)}
                        className="mt-0.5 flex items-start gap-1.5 font-mono text-[11px] break-all text-primary hover:underline"
                      >
                        <Copy className="size-3 shrink-0" /> {a.sha256}
                      </button>
                    ) : (
                      <p className="mt-0.5 font-mono text-[11px] text-muted-foreground">UNAVAILABLE</p>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </Panel>

      {/* RECOMMENDATIONS */}
      <Panel title="Recommended Security Actions" subtitle="Demo actions — nothing is blocked or changed in any real system">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {result.recommendations.map((r, i) => (
            <button
              key={r}
              onClick={() => toast.success("Demo security action executed.", { description: r })}
              className="flex items-center gap-3 rounded-lg border border-border/60 bg-muted/15 px-4 py-3 text-left text-sm transition-colors hover:border-primary/50 hover:bg-primary/10"
            >
              <span className="grid size-7 shrink-0 place-items-center rounded-md bg-primary/15 font-mono text-xs text-primary">
                {i + 1}
              </span>
              {r}
            </button>
          ))}
        </div>
      </Panel>
    </div>
  );
}

function headerRows(result: AnalysisResult) {
  const e = result.email;
  const suspiciousSender = result.senderAnalysis.risk !== "LOW";
  return [
    { name: "From", value: e.from, verdict: suspiciousSender ? "Suspicious" : "Clean" },
    { name: "Reply-To", value: e.replyTo, verdict: result.senderAnalysis.replyToMismatch ? "Suspicious" : "Analyzed" },
    { name: "Return-Path", value: e.returnPath, verdict: e.returnPath && e.returnPath !== e.from ? "Suspicious" : "Analyzed" },
    { name: "To", value: e.to, verdict: "Analyzed" },
    { name: "Subject", value: e.subject, verdict: "Analyzed" },
    { name: "Date", value: e.date, verdict: "Analyzed" },
    { name: "Message-ID", value: e.messageId, verdict: "Analyzed" },
    { name: "Received", value: e.received[0] ?? "UNKNOWN", verdict: "Investigated" },
    { name: "SPF", value: e.spfHeader, verdict: e.spfHeader === "PASS" ? "Clean" : e.spfHeader === "FAIL" ? "Suspicious" : "Analyzed" },
    { name: "DKIM", value: e.dkimHeader, verdict: e.dkimHeader === "PASS" ? "Clean" : e.dkimHeader === "FAIL" ? "Suspicious" : "Analyzed" },
    { name: "DMARC", value: e.dmarcHeader, verdict: e.dmarcHeader === "PASS" ? "Clean" : e.dmarcHeader === "FAIL" ? "Suspicious" : "Analyzed" },
  ];
}

export function Field({
  label,
  value,
  mono,
  small,
}: {
  label: string;
  value: string;
  mono?: boolean;
  small?: boolean;
}) {
  return (
    <div className="min-w-0">
      <p className="text-[10px] tracking-[0.14em] text-muted-foreground uppercase">{label}</p>
      <p className={`mt-0.5 break-words ${mono ? "font-mono text-xs" : small ? "text-xs" : "text-sm"}`}>{value || "UNKNOWN"}</p>
    </div>
  );
}
