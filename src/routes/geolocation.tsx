import { createFileRoute } from "@tanstack/react-router";
import { Globe2, MapPin, Server, ShieldAlert } from "lucide-react";
import { PageHeader, Panel } from "@/components/soc/Panel";
import { DemoTag, ReputationPill, SeverityPill } from "@/components/soc/Pill";
import { EmptyState } from "@/components/soc/EmptyState";
import { ThreatMap } from "@/components/soc/ThreatMap";
import { Field } from "@/components/soc/AnalysisResults";
import { useInvestigation } from "@/state/investigation-store";

export const Route = createFileRoute("/geolocation")({
  head: () => ({
    meta: [
      { title: "Threat Origin & Geolocation — MailSentinel AI" },
      {
        name: "description",
        content: "Map the originating IP of an analyzed email with country, region, city, ISP, ASN and risk scoring.",
      },
      { property: "og:title", content: "Threat Origin & Geolocation — MailSentinel AI" },
      { property: "og:description", content: "Interactive map of email origin infrastructure and its risk profile." },
    ],
  }),
  component: GeoPage,
});

function GeoPage() {
  const { current } = useInvestigation();

  if (!current) {
    return (
      <div className="space-y-6">
        <PageHeader title="Threat Origin & Geolocation Intelligence" />
        <EmptyState />
      </div>
    );
  }

  const origin = current.geolocation;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Threat Origin & Geolocation Intelligence"
        description="Where the analyzed message physically entered the internet, based on the Received header chain."
        action={<DemoTag label="Demo Geolocation Data" />}
      />

      <div className="grid gap-6 xl:grid-cols-[1.6fr_1fr]">
        <Panel title="Origin Map" icon={<Globe2 className="size-4" />} bodyClassName="p-4">
          {current.ipAnalysis.length ? (
            <ThreatMap points={current.ipAnalysis} />
          ) : (
            <p className="p-6 text-sm text-muted-foreground">
              No public IP addresses were found in this email, so no location can be mapped.
            </p>
          )}
          <p className="mt-3 text-[11px] text-muted-foreground">
            Locations come from the offline demo intelligence dataset. They illustrate infrastructure, not a real person.
          </p>
        </Panel>

        <div className="space-y-6">
          <Panel title="Origin Analysis" icon={<MapPin className="size-4" />} action={origin && <SeverityPill value={origin.risk} />}>
            {origin ? (
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="IP Address" value={origin.ip} mono />
                <Field label="Reputation" value={origin.reputation} />
                <Field label="Country" value={origin.country} />
                <Field label="Region" value={origin.region} />
                <Field label="City" value={origin.city} />
                <Field label="ISP" value={origin.isp} />
                <Field label="ASN" value={origin.asn} mono />
                <Field label="Abuse Score" value={`${origin.abuseScore} / 100`} />
                <Field label="Latitude" value={String(origin.lat)} mono />
                <Field label="Longitude" value={String(origin.lon)} mono />
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">UNKNOWN — no originating IP could be resolved.</p>
            )}
          </Panel>

          <Panel title="Origin Chain" icon={<ShieldAlert className="size-4" />}>
            <ol className="space-y-3">
              {[
                { label: "Email", value: current.email.subject },
                { label: "Originating IP", value: origin?.ip ?? "UNKNOWN" },
                { label: "Geolocation", value: origin ? `${origin.city}, ${origin.country}` : "UNKNOWN" },
                { label: "Threat Intelligence", value: `${current.iocs.length} IOCs · ${current.severity}` },
              ].map((s, i, arr) => (
                <li key={s.label} className="relative pl-6">
                  <span className="absolute top-1.5 left-0 size-2.5 rounded-full bg-primary" />
                  {i < arr.length - 1 && <span className="absolute top-4 left-[4px] h-full w-px bg-border" />}
                  <p className="text-[10px] tracking-[0.14em] text-muted-foreground uppercase">{s.label}</p>
                  <p className="truncate text-sm">{s.value}</p>
                </li>
              ))}
            </ol>
          </Panel>
        </div>
      </div>

      <Panel title="All Observed Infrastructure" icon={<Server className="size-4" />} bodyClassName="p-0">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border/60 text-left text-[11px] tracking-[0.12em] text-muted-foreground uppercase">
                <th className="px-5 py-3 font-medium">IP</th>
                <th className="px-5 py-3 font-medium">City</th>
                <th className="px-5 py-3 font-medium">Country</th>
                <th className="px-5 py-3 font-medium">ISP</th>
                <th className="px-5 py-3 font-medium">ASN</th>
                <th className="px-5 py-3 font-medium">Coordinates</th>
                <th className="px-5 py-3 font-medium">Reputation</th>
              </tr>
            </thead>
            <tbody>
              {current.ipAnalysis.map((ip) => (
                <tr key={ip.ip} className="border-b border-border/40 last:border-0">
                  <td className="px-5 py-3 font-mono text-xs">{ip.ip}</td>
                  <td className="px-5 py-3 text-xs">{ip.city}</td>
                  <td className="px-5 py-3 text-xs">{ip.country}</td>
                  <td className="px-5 py-3 text-xs">{ip.isp}</td>
                  <td className="px-5 py-3 font-mono text-xs">{ip.asn}</td>
                  <td className="px-5 py-3 font-mono text-xs">
                    {ip.lat.toFixed(3)}, {ip.lon.toFixed(3)}
                  </td>
                  <td className="px-5 py-3">
                    <ReputationPill value={ip.reputation} />
                  </td>
                </tr>
              ))}
              {current.ipAnalysis.length === 0 && (
                <tr>
                  <td className="px-5 py-6 text-sm text-muted-foreground" colSpan={7}>
                    UNKNOWN — no public IP addresses were present in this message.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}
