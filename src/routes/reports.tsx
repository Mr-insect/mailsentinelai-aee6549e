import { createFileRoute } from "@tanstack/react-router";
import { Printer, ScrollText } from "lucide-react";
import { PageHeader, Panel } from "@/components/soc/Panel";
import { AuthPill, DemoTag, SeverityPill } from "@/components/soc/Pill";
import { EmptyState } from "@/components/soc/EmptyState";
import { Field } from "@/components/soc/AnalysisResults";
import { Button } from "@/components/ui/button";
import { useInvestigation } from "@/state/investigation-store";
import { IS_DEMO_MODE } from "@/services/emailAnalysisService";

export const Route = createFileRoute("/reports")({
  head: () => ({
    meta: [
      { title: "Investigation Report — MailSentinel AI" },
      {
        name: "description",
        content:
          "Printable SOC forensic report: verdict, authentication, threat intelligence, IOCs, geolocation, timeline, attack chain, evidence provenance and AI analyst assessment.",
      },
      { property: "og:title", content: "Investigation Report — MailSentinel AI" },
      { property: "og:description", content: "Generate a complete, printable email threat investigation report." },
    ],
  }),
  component: ReportsPage,
});

const PRINT_CSS = `
@media print {
  body { background: #fff !important; color: #111 !important; }
  nav, aside, .no-print { display: none !important; }
  section, li, tr { break-inside: avoid; }
}
`;

const PROVENANCE_LEGEND = [
  { tag: "LIVE INTELLIGENCE", desc: "Confirmed results from live providers (VirusTotal, AbuseIPDB, Google, geolocation)." },
  { tag: "AI ANALYSIS", desc: "Model-generated assessment — never treated as confirmed threat intelligence." },
  { tag: "LOCAL HEURISTICS", desc: "Deterministic parser and rule-based findings from the message itself." },
  { tag: "UNKNOWN / UNAVAILABLE", desc: "No reliable evidence existed. The tool does not fabricate answers." },
];

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
  const isLive = r.mode === "LIVE" && !IS_DEMO_MODE;
  const providerFailures = Object.entries(r.providerHealth ?? {}).filter(
    ([, p]) => p.configured && !["CONNECTED", "DISABLED"].includes(String(p.status)),
  );

  return (
    <div className="space-y-6">
      <style>{PRINT_CSS}</style>
      <PageHeader
        title="Investigation Report"
        description={`Full forensic summary for ${r.investigationId}.`}
        action={
          <div className="flex items-center gap-3">
            <DemoTag label={isLive ? "Live Intelligence" : "Demo Intelligence"} />
            <Button className="no-print" onClick={() => window.print()}>
              <Printer className="size-4" /> Print Report
            </Button>
          </div>
        }
      />

      <Panel title="SOC Investigation Report" icon={<ScrollText className="size-4" />} action={<SeverityPill value={r.severity} />}>
        <div className="mb-8 rounded-lg border border-border/60 bg-muted/10 p-4">
          <h3 className="mb-3 text-xs font-semibold tracking-[0.16em] text-primary uppercase">Evidence Provenance Legend</h3>
          <div className="grid gap-2 sm:grid-cols-2">
            {PROVENANCE_LEGEND.map((p) => (
              <div key={p.tag} className="rounded-md border border-border/50 bg-background/60 px-3 py-2">
                <p className="text-[11px] font-semibold tracking-wider text-foreground uppercase">{p.tag}</p>
                <p className="mt-0.5 text-[11px] text-muted-foreground">{p.desc}</p>
              </div>
            ))}
          </div>
        </div>

        <div className="space-y-8">
          <Section title="Case">
            <div className="grid gap-4 sm:grid-cols-3">
              <Field label="Investigation ID" value={r.investigationId} mono />
              <Field label="Timestamp" value={new Date(r.analyzedAt).toLocaleString()} />
              <Field label="Analysis Mode" value={r.mode === "LIVE" ? "LIVE INTELLIGENCE + AI" : "LOCAL HEURISTICS (DEMO)"} />
              <Field label="Threat Verdict" value={r.threatType} />
              <Field label="Risk Score" value={`${r.riskScore} / 100`} />
              <Field label="Severity" value={r.severity} />
              <Field label="Message SHA-256" value={r.messageSha256 || "UNAVAILABLE"} mono />
              <Field label="Sender" value={r.email.from} mono />
              <Field label="Recipient" value={r.email.to} mono />
              <Field label="Subject" value={r.email.subject} />
            </div>
          </Section>

          {r.confidenceBreakdown && (
            <Section title="Confidence Dimensions">
              <div className="grid gap-4 sm:grid-cols-3">
                {[
                  ["Parser Confidence", r.confidenceBreakdown.parserConfidence],
                  ["Evidence Confidence", r.confidenceBreakdown.evidenceConfidence],
                  ["Threat-Intel Confidence", r.confidenceBreakdown.threatIntelConfidence],
                  ["AI Confidence", r.confidenceBreakdown.aiConfidence],
                  ["Geolocation Confidence", r.confidenceBreakdown.geolocationConfidence],
                  ["Final Verdict Confidence", r.confidenceBreakdown.finalVerdictConfidence],
                ]
                  .filter(([, v]) => v !== undefined && v !== null)
                  .map(([label, v]) => (
                    <Field key={String(label)} label={String(label)} value={`${v}%`} />
                  ))}
              </div>
              <p className="mt-3 text-[11px] text-muted-foreground">
                Geolocation confidence describes positional accuracy — it is never mixed into the threat confidence.
              </p>
            </Section>
          )}

          <Section title="Authentication">
            <div className="flex flex-wrap gap-3">
              {r.authenticationAnalysis.map((a) => (
                <span key={a.name} className="inline-flex items-center gap-2 rounded-lg border border-border/60 px-3 py-2 text-sm">
                  {a.name} <AuthPill value={a.status} />
                </span>
              ))}
            </div>
          </Section>

          <Section title="Score Breakdown">
            {r.scoreBreakdown?.length ? (
              <ul className="space-y-1.5 text-sm">
                {r.scoreBreakdown.map((b) => (
                  <li key={`${b.category}-${b.points}`} className="flex items-start justify-between gap-4 break-words">
                    <span>
                      <span className="font-medium">{b.category}</span>
                      <span className="ml-2 text-xs text-muted-foreground">{b.reason}</span>
                    </span>
                    <span className={`shrink-0 font-mono text-xs tabular-nums ${b.points >= 0 ? "text-critical" : "text-safe"}`}>
                      {b.points >= 0 ? `+${b.points}` : b.points}
                    </span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted-foreground">UNKNOWN — no breakdown recorded for this analysis.</p>
            )}
          </Section>

          <Section title="Domain Intelligence">
            <ReportList
              rows={r.domainAnalysis.map(
                (d) =>
                  `${d.domain} — ${d.reputation}${d.ageDays != null ? `, registered ${d.ageDays} days ago (${d.registrar || "registrar unavailable"})` : ", registration data unavailable"}`,
              )}
            />
          </Section>

          <Section title="URL Intelligence">
            <ReportList rows={r.urlAnalysis.map((u) => `${u.url} — ${u.reputation}${u.indicators?.length ? ` [${u.indicators.join(", ")}]` : ""}`)} />
          </Section>

          <Section title="IP Intelligence & Geolocation">
            <ReportList
              rows={r.ipAnalysis.map(
                (ip) =>
                  `${ip.ip} — ${ip.city || "?"}, ${ip.country || "?"}${ip.accuracy_radius_km ? ` (accuracy radius ${ip.accuracy_radius_km} km)` : ""} · ${ip.isp || "ISP unavailable"} (${ip.asn || "ASN unavailable"}) · abuse ${ip.abuseScore}/100 · ${ip.reputation}`,
              )}
            />
            <p className="mt-2 text-[11px] text-muted-foreground">
              Approximate IP geolocation — coordinates reflect the network's registered location, not an exact street or
              home address. Accuracy radius is shown when the provider supplies it.
            </p>
          </Section>

          <Section title="Extracted IOCs">
            <ReportList rows={r.iocs.map((i) => `${i.type}: ${i.value} (${i.reputation})`)} mono />
          </Section>

          <Section title="Attachments">
            <ReportList
              rows={r.attachments.map(
                (a) => `${a.filename} — ${a.status}${a.verdict && a.verdict !== a.status ? ` (${a.verdict})` : ""} · ${a.sizeLabel} · SHA-256 ${a.sha256 || "UNAVAILABLE"}`,
              )}
            />
            <p className="mt-2 text-[11px] text-muted-foreground">
              UNKNOWN is never treated as CLEAN. Hash lookup (SHA-256) is the default; files are uploaded to third-party
              scanners only when explicitly enabled by policy.
            </p>
          </Section>

          <Section title="Forensic Timeline">
            <ReportList rows={r.timeline.map((t) => `${t.time} — ${t.label}: ${t.detail}${t.evidenceSource ? ` [evidence: ${t.evidenceSource}]` : ""}`)} />
          </Section>

          <Section title="Attack Chain">
            {r.attackChain.length ? (
              <ul className="space-y-2 text-sm">
                {r.attackChain.map((n) => (
                  <li key={n.label} className="break-words">
                    <span className="font-semibold">{n.label}</span>
                    {n.stage ? <span className="ml-2 text-[11px] text-muted-foreground">({n.stage})</span> : null}
                    {" — "}
                    {n.detail}
                    {n.evidence ? <span className="ml-1 text-xs text-muted-foreground">[evidence: {n.evidence}]</span> : null}
                    {n.confidence !== undefined ? <span className="ml-1 font-mono text-xs text-muted-foreground">confidence {n.confidence}%</span> : null}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted-foreground">
                UNKNOWN — no evidence-supported attack-chain stage could be constructed for this message.
              </p>
            )}
          </Section>

          {r.evidence?.length ? (
            <Section title="Evidence Provenance">
              <ul className="space-y-1.5 text-xs">
                {r.evidence.slice(0, 12).map((f) => (
                  <li key={f.findingId} className="break-words border-b border-border/30 pb-1.5">
                    <span className="font-mono text-muted-foreground">{f.status.toUpperCase()}</span>{" "}
                    <span className="font-medium">{f.title}</span> — {f.observedValue}{" "}
                    <span className="text-muted-foreground">
                      [source: {f.source}
                      {f.provider && f.provider !== "none" ? ` · provider: ${f.provider}` : ""} · {f.observedVsInferred}]
                    </span>
                  </li>
                ))}
              </ul>
            </Section>
          ) : null}

          <Section title="AI Analyst Assessment">
            {r.aiAssessment?.used ? (
              <div className="space-y-3 text-sm">
                <p className="rounded-md border border-warning/40 bg-warning/10 px-3 py-2 text-xs text-warning">
                  AI ANALYSIS — model-generated interpretation, never confirmed threat intelligence.
                </p>
                {r.aiAssessment.executiveSummary && <p>{r.aiAssessment.executiveSummary}</p>}
                {r.aiAssessment.confirmedFindings?.length ? (
                  <ReportList rows={r.aiAssessment.confirmedFindings.map((f) => `CONFIRMED: ${f}`)} />
                ) : null}
                {r.aiAssessment.suspectedFindings?.length ? (
                  <ReportList rows={r.aiAssessment.suspectedFindings.map((f) => `INFERRED: ${f}`)} />
                ) : null}
                {r.aiAssessment.unknowns?.length ? <ReportList rows={r.aiAssessment.unknowns.map((f) => `UNKNOWN: ${f}`)} /> : null}
                {r.aiAssessment.attackTechniques?.length ? (
                  <p className="text-xs text-muted-foreground">Techniques supported by evidence: {r.aiAssessment.attackTechniques.join("; ")}</p>
                ) : null}
                {r.aiAssessment.reasoningSummary && <p className="text-xs text-muted-foreground">Reasoning: {r.aiAssessment.reasoningSummary}</p>}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">
                UNAVAILABLE — the AI analyst did not return an assessment for this investigation (disabled, unreachable, or
                invalid output). No AI-derived claims are included.
              </p>
            )}
          </Section>

          <Section title="Provider Status">
            {providerFailures.length ? (
              <ReportList rows={providerFailures.map(([name, p]) => `${name.toUpperCase()} — ${String(p.status).toUpperCase()}`)} />
            ) : (
              <p className="text-sm text-muted-foreground">All configured providers responded normally during this investigation.</p>
            )}
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
