import { createFileRoute } from "@tanstack/react-router";
import { Globe, Link2, Server, ShieldAlert } from "lucide-react";
import { PageHeader, Panel } from "@/components/soc/Panel";
import { DemoTag, ReputationPill, SeverityPill } from "@/components/soc/Pill";
import { EmptyState } from "@/components/soc/EmptyState";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useInvestigation } from "@/state/investigation-store";

export const Route = createFileRoute("/threat-intelligence")({
  head: () => ({
    meta: [
      { title: "Threat Intelligence — MailSentinel AI" },
      {
        name: "description",
        content: "Domain, IP and URL intelligence for the infrastructure observed in an analyzed email.",
      },
      { property: "og:title", content: "Threat Intelligence — MailSentinel AI" },
      { property: "og:description", content: "Reputation, age, hosting and abuse scoring for observed threat infrastructure." },
    ],
  }),
  component: IntelPage,
});

function IntelPage() {
  const { current } = useInvestigation();

  if (!current) {
    return (
      <div className="space-y-6">
        <PageHeader title="Threat Intelligence" />
        <EmptyState description="Domain, IP and URL intelligence is populated from the email you analyze." />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Threat Intelligence"
        description="Infrastructure observed in the current investigation, enriched with offline demo intelligence."
        action={<DemoTag />}
      />

      <Panel title="Infrastructure Intelligence" icon={<ShieldAlert className="size-4" />}>
        <Tabs defaultValue="domain">
          <TabsList>
            <TabsTrigger value="domain">
              <Globe className="size-4" /> Domain
            </TabsTrigger>
            <TabsTrigger value="ip">
              <Server className="size-4" /> IP
            </TabsTrigger>
            <TabsTrigger value="url">
              <Link2 className="size-4" /> URL
            </TabsTrigger>
          </TabsList>

          <TabsContent value="domain" className="mt-4 overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border/60 text-left text-[11px] tracking-[0.12em] text-muted-foreground uppercase">
                  <th className="px-3 py-3 font-medium">Domain</th>
                  <th className="px-3 py-3 font-medium">Age</th>
                  <th className="px-3 py-3 font-medium">Registrar</th>
                  <th className="px-3 py-3 font-medium">DNS</th>
                  <th className="px-3 py-3 font-medium">Reputation</th>
                  <th className="px-3 py-3 font-medium">Risk</th>
                </tr>
              </thead>
              <tbody>
                {current.domainAnalysis.map((d) => (
                  <tr key={d.domain} className="border-b border-border/40 last:border-0">
                    <td className="px-3 py-3 font-mono text-xs break-all">
                      {d.domain}
                      {d.lookalike && <span className="ml-2 text-[11px] text-critical">lookalike</span>}
                    </td>
                    <td className="px-3 py-3 text-xs">{d.ageDays === null ? "UNKNOWN" : `${d.ageDays} days`}</td>
                    <td className="px-3 py-3 text-xs">{d.registrar}</td>
                    <td className="px-3 py-3 text-xs text-muted-foreground">{d.dns}</td>
                    <td className="px-3 py-3">
                      <ReputationPill value={d.reputation} />
                    </td>
                    <td className="px-3 py-3">
                      <SeverityPill value={d.risk} />
                    </td>
                  </tr>
                ))}
                {current.domainAnalysis.length === 0 && <EmptyRow colSpan={6} />}
              </tbody>
            </table>
          </TabsContent>

          <TabsContent value="ip" className="mt-4 overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border/60 text-left text-[11px] tracking-[0.12em] text-muted-foreground uppercase">
                  <th className="px-3 py-3 font-medium">IP</th>
                  <th className="px-3 py-3 font-medium">Country</th>
                  <th className="px-3 py-3 font-medium">ASN</th>
                  <th className="px-3 py-3 font-medium">ISP</th>
                  <th className="px-3 py-3 font-medium">Reputation</th>
                  <th className="px-3 py-3 font-medium">Abuse</th>
                  <th className="px-3 py-3 font-medium">Risk</th>
                </tr>
              </thead>
              <tbody>
                {current.ipAnalysis.map((ip) => (
                  <tr key={ip.ip} className="border-b border-border/40 last:border-0">
                    <td className="px-3 py-3 font-mono text-xs">{ip.ip}</td>
                    <td className="px-3 py-3 text-xs">{ip.country}</td>
                    <td className="px-3 py-3 font-mono text-xs">{ip.asn}</td>
                    <td className="px-3 py-3 text-xs">{ip.isp}</td>
                    <td className="px-3 py-3">
                      <ReputationPill value={ip.reputation} />
                    </td>
                    <td className="px-3 py-3 font-mono text-xs">{ip.abuseScore}/100</td>
                    <td className="px-3 py-3">
                      <SeverityPill value={ip.risk} />
                    </td>
                  </tr>
                ))}
                {current.ipAnalysis.length === 0 && <EmptyRow colSpan={7} />}
              </tbody>
            </table>
          </TabsContent>

          <TabsContent value="url" className="mt-4 overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border/60 text-left text-[11px] tracking-[0.12em] text-muted-foreground uppercase">
                  <th className="px-3 py-3 font-medium">URL</th>
                  <th className="px-3 py-3 font-medium">Domain</th>
                  <th className="px-3 py-3 font-medium">HTTPS</th>
                  <th className="px-3 py-3 font-medium">Redirects</th>
                  <th className="px-3 py-3 font-medium">Reputation</th>
                  <th className="px-3 py-3 font-medium">Risk</th>
                </tr>
              </thead>
              <tbody>
                {current.urlAnalysis.map((u) => (
                  <tr key={u.url} className="border-b border-border/40 last:border-0">
                    <td className="max-w-sm px-3 py-3 font-mono text-xs break-all">{u.url}</td>
                    <td className="px-3 py-3 font-mono text-xs">{u.domain}</td>
                    <td className="px-3 py-3 text-xs">{u.https ? "Yes" : "No"}</td>
                    <td className="px-3 py-3 text-xs">{u.redirect ? "Yes" : "No"}</td>
                    <td className="px-3 py-3">
                      <ReputationPill value={u.reputation} />
                    </td>
                    <td className="px-3 py-3">
                      <SeverityPill value={u.risk} />
                    </td>
                  </tr>
                ))}
                {current.urlAnalysis.length === 0 && <EmptyRow colSpan={6} />}
              </tbody>
            </table>
          </TabsContent>
        </Tabs>
      </Panel>
    </div>
  );
}

function EmptyRow({ colSpan }: { colSpan: number }) {
  return (
    <tr>
      <td colSpan={colSpan} className="px-3 py-8 text-center text-sm text-muted-foreground">
        UNKNOWN — nothing of this type was found in the analyzed email.
      </td>
    </tr>
  );
}
