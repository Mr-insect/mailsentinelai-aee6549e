import { createFileRoute } from "@tanstack/react-router";
import { Cpu, Plug, ServerCog, ShieldCheck } from "lucide-react";
import { PageHeader, Panel } from "@/components/soc/Panel";
import { DemoTag } from "@/components/soc/Pill";
import { API_ROUTES, IS_DEMO_MODE } from "@/services/emailAnalysisService";

export const Route = createFileRoute("/settings")({
  head: () => ({
    meta: [
      { title: "Settings — MailSentinel AI" },
      {
        name: "description",
        content: "Analysis mode, backend status and the future API integrations MailSentinel AI can connect to.",
      },
      { property: "og:title", content: "Settings — MailSentinel AI" },
      { property: "og:description", content: "System status and integration roadmap for MailSentinel AI." },
    ],
  }),
  component: SettingsPage,
});

const STATUS = [
  { label: "Analysis Mode", value: "Demo Intelligence", tone: "text-primary" },
  { label: "API Integration", value: "Not Connected", tone: "text-warning" },
  { label: "Backend", value: "Demo Mode (in-browser engine)", tone: "text-primary" },
  { label: "System Status", value: "Online", tone: "text-safe" },
];

const FUTURE = [
  "SPF verification API",
  "DKIM verification API",
  "DMARC policy API",
  "IP geolocation API",
  "Threat intelligence feed",
  "Virus / URL reputation API",
];

function SettingsPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Settings"
        description="MailSentinel AI runs entirely in your browser. No API keys, accounts or network services are required."
        action={<DemoTag />}
      />

      <div className="grid gap-6 lg:grid-cols-2">
        <Panel title="System" icon={<ShieldCheck className="size-4" />}>
          <div className="grid gap-4 sm:grid-cols-2">
            {STATUS.map((s) => (
              <div key={s.label} className="rounded-lg border border-border/60 bg-muted/15 p-4">
                <p className="text-[10px] tracking-[0.14em] text-muted-foreground uppercase">{s.label}</p>
                <p className={`mt-1 text-sm font-medium ${s.tone}`}>{s.value}</p>
              </div>
            ))}
          </div>
          <p className="mt-4 text-xs text-muted-foreground">
            Live mode is {IS_DEMO_MODE ? "inactive" : "active"}. Every verdict currently comes from the local rule-based
            engine and is labelled as demo intelligence throughout the interface.
          </p>
        </Panel>

        <Panel title="Future Integrations" icon={<Plug className="size-4" />}>
          <ul className="grid gap-2 sm:grid-cols-2">
            {FUTURE.map((f) => (
              <li key={f} className="flex items-center justify-between rounded-lg border border-border/60 bg-muted/15 px-3 py-2 text-sm">
                {f}
                <span className="text-[10px] tracking-[0.14em] text-muted-foreground uppercase">Planned</span>
              </li>
            ))}
          </ul>
          <p className="mt-4 text-xs text-muted-foreground">
            None of these are required for the demo. Keys would live on the backend only — never in the browser.
          </p>
        </Panel>
      </div>

      <Panel title="Backend Contract" subtitle="Endpoints the service layer will call once a FastAPI backend is connected" icon={<ServerCog className="size-4" />}>
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
          Set <span className="font-mono text-foreground">VITE_MAILSENTINEL_API_BASE</span> to point the service layer at a
          Python/FastAPI backend. If a request fails, the app silently falls back to the demo engine so the interface never
          breaks.
        </p>
      </Panel>
    </div>
  );
}
