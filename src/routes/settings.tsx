import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { Cpu, Plug, ServerCog, ShieldCheck } from "lucide-react";
import { PageHeader, Panel } from "@/components/soc/Panel";
import { API_ROUTES, IS_DEMO_MODE, emailAnalysisService, type ProviderHealthStatus } from "@/services/emailAnalysisService";

export const Route = createFileRoute("/settings")({
  head: () => ({
    meta: [
      { title: "Settings — MailSentinel AI" },
      {
        name: "description",
        content: "Analysis mode, live provider health (VirusTotal, AbuseIPDB, Google, OpenAI, geolocation) and backend status for MailSentinel AI.",
      },
      { property: "og:title", content: "Settings — MailSentinel AI" },
      { property: "og:description", content: "Provider health, system status and API integration overview." },
    ],
  }),
  component: SettingsPage,
});

const PROVIDER_LABELS: Record<string, string> = {
  openai: "OpenAI (AI Analyst)",
  virustotal: "VirusTotal",
  abuseipdb: "AbuseIPDB",
  google: "Google Safe Browsing",
  geolocation: "Geolocation Provider",
};

const STATUS_CLASSES: Record<string, string> = {
  CONNECTED: "border-safe/40 bg-safe/10 text-safe",
  DISABLED: "border-border/60 bg-muted/30 text-muted-foreground",
  RATE_LIMITED: "border-warning/50 bg-warning/10 text-warning",
  ERROR: "border-critical/50 bg-critical/10 text-critical",
  TIMEOUT: "border-warning/50 bg-warning/10 text-warning",
  NOT_CONFIGURED: "border-border/60 bg-muted/30 text-muted-foreground",
};

function SettingsPage() {
  const [providers, setProviders] = useState<Record<string, ProviderHealthStatus> | null>(null);

  useEffect(() => {
    let disposed = false;
    emailAnalysisService.providerHealth().then((p) => {
      if (!disposed) setProviders(p);
    });
    return () => {
      disposed = true;
    };
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Settings"
        description="Analysis mode, live provider health and backend configuration. API keys live only in backend environment variables — never in the browser and never on this page."
      />

      <Panel title="Provider Health" subtitle="Live status from GET /api/health/providers (sanitized — no secrets)" icon={<ShieldCheck className="size-4" />}>
        {!IS_DEMO_MODE ? (
          providers ? (
            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
              {Object.entries(providers).map(([key, p]) => (
                <div key={key} className="rounded-lg border border-border/60 bg-muted/15 p-4">
                  <div className="flex items-center justify-between gap-2">
                    <p className="text-sm font-medium">{PROVIDER_LABELS[key] ?? key}</p>
                    <span className={`rounded-full border px-2.5 py-0.5 text-[10px] font-semibold tracking-wider uppercase ${STATUS_CLASSES[p.status] ?? STATUS_CLASSES.ERROR}`}>
                      {p.status}
                    </span>
                  </div>
                  <p className="mt-2 text-[11px] text-muted-foreground">
                    {p.model ? `Model: ${p.model} · ` : ""}
                    {p.provider ? `Provider: ${p.provider} · ` : ""}
                    {p.note ?? (p.configured ? "Key configured on the backend." : "No key configured — provider unavailable in results.")}
                  </p>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">
              Connecting to the backend provider-health endpoint… If this message persists, the backend may be unreachable.
            </p>
          )
        ) : (
          <p className="text-sm text-muted-foreground">
            Offline demo mode — the in-browser analysis engine is active and no external providers are queried.
            Set <span className="font-mono text-foreground">VITE_MAILSENTINEL_API_BASE</span> to connect the FastAPI
            backend and view live provider status here.
          </p>
        )}
      </Panel>

      <Panel title="Backend Contract" subtitle="Endpoints the service layer calls" icon={<ServerCog className="size-4" />}>
        <div className="grid gap-2 sm:grid-cols-2">
          {Object.entries(API_ROUTES).map(([name, path]) => (
            <div key={path} className="rounded-lg border border-border/60 bg-background/50 px-4 py-3">
              <p className="font-mono text-xs text-primary">{path}</p>
              <p className="mt-0.5 text-[11px] text-muted-foreground">{name}</p>
            </div>
          ))}
        </div>
        <p className="mt-4 flex items-start gap-2 text-xs text-muted-foreground">
          <Cpu className="mt-0.5 size-4 shrink-0 text-primary" />
          Provider keys (VirusTotal, AbuseIPDB, Google Safe Browsing, OpenAI) are configured in the backend{" "}
          <span className="font-mono text-foreground">.env</span> only. This page never receives or displays secrets.
        </p>
      </Panel>
    </div>
  );
}
