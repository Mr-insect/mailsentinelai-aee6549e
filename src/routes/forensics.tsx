import { createFileRoute } from "@tanstack/react-router";
import { ArrowDown, Clock, Fingerprint, GitBranch } from "lucide-react";
import { PageHeader, Panel } from "@/components/soc/Panel";
import { DemoTag, SeverityPill } from "@/components/soc/Pill";
import { EmptyState } from "@/components/soc/EmptyState";
import { Field } from "@/components/soc/AnalysisResults";
import { severityHex } from "@/components/soc/severity";
import { useInvestigation } from "@/state/investigation-store";

export const Route = createFileRoute("/forensics")({
  head: () => ({
    meta: [
      { title: "Forensic Investigation — MailSentinel AI" },
      {
        name: "description",
        content: "Investigation timeline, attack chain and evidence summary for an analyzed email threat.",
      },
      { property: "og:title", content: "Forensic Investigation — MailSentinel AI" },
      { property: "og:description", content: "Step-by-step forensic reconstruction of an email attack." },
    ],
  }),
  component: ForensicsPage,
});

function ForensicsPage() {
  const { current } = useInvestigation();

  if (!current) {
    return (
      <div className="space-y-6">
        <PageHeader title="Forensic Investigation" />
        <EmptyState description="Run an analysis to build the forensic timeline and attack chain." />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Forensic Investigation"
        description="Reconstruction of how the message reached the mailbox and how it was classified."
        action={<DemoTag />}
      />

      <Panel title="Case Summary" icon={<Fingerprint className="size-4" />} action={<SeverityPill value={current.severity} />}>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Field label="Investigation ID" value={current.investigationId} mono />
          <Field label="Status" value="COMPLETED" />
          <Field label="Threat Type" value={current.threatType} />
          <Field label="Risk Score" value={`${current.riskScore} / 100`} />
          <Field label="Sender" value={current.email.from} mono />
          <Field label="Recipient" value={current.email.to} mono />
          <Field label="Subject" value={current.email.subject} />
          <Field label="Analyzed At" value={new Date(current.analyzedAt).toLocaleString()} />
        </div>
      </Panel>

      <div className="grid gap-6 xl:grid-cols-2">
        <Panel title="Investigation Timeline" icon={<Clock className="size-4" />}>
          <ol className="space-y-4">
            {current.timeline.map((t, i, arr) => (
              <li key={`${t.time}-${t.label}`} className="relative pl-8">
                <span className="absolute top-1 left-0 grid size-5 place-items-center rounded-full border border-primary/50 bg-primary/15">
                  <span className="size-1.5 rounded-full bg-primary" />
                </span>
                {i < arr.length - 1 && <span className="absolute top-6 left-[9px] h-[calc(100%+0.4rem)] w-px bg-border" />}
                <p className="font-mono text-xs text-primary">{t.time}</p>
                <p className="text-sm font-medium">{t.label}</p>
                <p className="text-xs text-muted-foreground">{t.detail}</p>
              </li>
            ))}
          </ol>
        </Panel>

        <Panel title="Attack Chain" icon={<GitBranch className="size-4" />}>
          <div className="space-y-2">
            {current.attackChain.map((node, i, arr) => {
              const color = severityHex[node.severity];
              return (
                <div key={node.label}>
                  <div
                    className="rounded-lg border px-4 py-3"
                    style={{
                      borderColor: `color-mix(in oklch, ${color} 45%, transparent)`,
                      background: `color-mix(in oklch, ${color} 10%, transparent)`,
                    }}
                  >
                    <p className="text-[10px] font-semibold tracking-[0.18em] uppercase" style={{ color }}>
                      {node.label}
                    </p>
                    <p className="mt-0.5 truncate font-mono text-xs text-foreground/90">{node.detail}</p>
                  </div>
                  {i < arr.length - 1 && (
                    <div className="flex justify-center py-1">
                      <ArrowDown className="size-4 text-muted-foreground" />
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </Panel>
      </div>
    </div>
  );
}
