import { createFileRoute } from "@tanstack/react-router";
import { Printer, ScrollText } from "lucide-react";
import { PageHeader, Panel } from "@/components/soc/Panel";
import { AuthPill, DemoTag, SeverityPill } from "@/components/soc/Pill";
import { EmptyState } from "@/components/soc/EmptyState";
import { Field } from "@/components/soc/AnalysisResults";
import { Button } from "@/components/ui/button";
import { useInvestigation } from "@/state/investigation-store";

export const Route = createFileRoute("/reports")({
  head: () => ({
    meta: [
      { title: "Investigation Report — MailSentinel AI" },
      {
        name: "description",
        content: "Printable forensic report covering verdict, authentication, infrastructure, IOCs, timeline and recommended actions.",
      },
      { property: "og:title", content: "Investigation Report — MailSentinel AI" },
      { property: "og:description", content: "Generate a complete, printable email threat investigation report." },
    ],
  }),
  component: ReportsPage,
});

function ReportsPage() {
  const { current } = useInvestigation();

  if (!current) {
    return (
      <div className="space-y-6">
        <PageHeader title="Investigation Report" />
        <EmptyState description="Analyze an email first — the report is generated from that investigation." />
      </div>
    );
  }

  const r = current;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Investigation Report"
        description={`Full forensic summary for ${r.investigationId}.`}
        action={
          <div className="flex items-center gap-3">
            <DemoTag />
            <Button onClick={() => window.print()}>
              <Printer className="size-4" /> Print Report
            </Button>
          </div>
        }
      />

      <Panel title="Generate Investigation Report" icon={<ScrollText className="size-4" />} action={<SeverityPill value={r.severity} />}>
        <div className="space-y-8">
          <Section title="Case">
            <div className="grid gap-4 sm:grid-cols-3">
              <Field label="Investigation ID" value={r.investigationId} mono />
              <Field label="Timestamp" value={new Date(r.analyzedAt).toLocaleString()} />
              <Field label="Analysis Mode" value="AI-Assisted Demo Analysis" />
              <Field label="Threat Verdict" value={r.threatType} />
              <Field label="Risk Score" value={`${r.riskScore} / 100`} />
              <Field label="Confidence" value={`${r.confidence}%`} />
              <Field label="Sender" value={r.email.from} mono />
              <Field label="Recipient" value={r.email.to} mono />
              <Field label="Subject" value={r.email.subject} />
            </div>
          </Section>

          <Section title="Authentication">
            <div className="flex flex-wrap gap-3">
              {r.authenticationAnalysis.map((a) => (
                <span key={a.name} className="inline-flex items-center gap-2 rounded-lg border border-border/60 px-3 py-2 text-sm">
                  {a.name} <AuthPill value={a.status} />
                </span>
              ))}
            </div>
          </Section>

          <Section title="Domain Intelligence">
            <ReportList
              rows={r.domainAnalysis.map((d) => `${d.domain} — ${d.reputation}, registered ${d.ageDays} days ago (${d.registrar})`)}
            />
          </Section>

          <Section title="URL Intelligence">
            <ReportList rows={r.urlAnalysis.map((u) => `${u.url} — ${u.reputation} (${u.risk})`)} />
          </Section>

          <Section title="IP Intelligence & Geolocation">
            <ReportList
              rows={r.ipAnalysis.map(
                (ip) => `${ip.ip} — ${ip.city}, ${ip.country} · ${ip.isp} (${ip.asn}) · abuse ${ip.abuseScore}/100 · ${ip.reputation}`,
              )}
            />
            <p className="mt-2 text-[11px] text-muted-foreground">Demo geolocation data — infrastructure only, not a person.</p>
          </Section>

          <Section title="Extracted IOCs">
            <ReportList rows={r.iocs.map((i) => `${i.type}: ${i.value} (${i.reputation})`)} mono />
          </Section>

          <Section title="Attachments">
            <ReportList rows={r.attachments.map((a) => `${a.filename} — ${a.status} · ${a.sizeLabel} · ${a.sha256.slice(0, 24)}…`)} />
          </Section>

          <Section title="Forensic Timeline">
            <ReportList rows={r.timeline.map((t) => `${t.time} — ${t.label}: ${t.detail}`)} />
          </Section>

          <Section title="Attack Chain">
            <p className="font-mono text-xs break-words text-muted-foreground">
              {r.attackChain.map((n) => n.label).join("  →  ")}
            </p>
          </Section>

          <Section title="Recommended Actions">
            <ReportList rows={r.recommendations} />
          </Section>
        </div>
      </Panel>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="mb-3 border-b border-border/60 pb-2 text-xs font-semibold tracking-[0.16em] text-primary uppercase">{title}</h3>
      {children}
    </div>
  );
}

function ReportList({ rows, mono }: { rows: string[]; mono?: boolean }) {
  if (rows.length === 0) return <p className="text-sm text-muted-foreground">UNKNOWN — nothing recorded for this section.</p>;
  return (
    <ul className={`space-y-1.5 ${mono ? "font-mono text-xs" : "text-sm"}`}>
      {rows.map((row) => (
        <li key={row} className="break-words text-foreground/90">
          • {row}
        </li>
      ))}
    </ul>
  );
}
