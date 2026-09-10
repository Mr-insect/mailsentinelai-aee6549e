import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { Copy, Radar, Search } from "lucide-react";
import { toast } from "sonner";
import { PageHeader, Panel } from "@/components/soc/Panel";
import { DemoTag, ReputationPill, SeverityPill } from "@/components/soc/Pill";
import { EmptyState } from "@/components/soc/EmptyState";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { useInvestigation } from "@/state/investigation-store";
import type { Ioc } from "@/lib/types";

export const Route = createFileRoute("/ioc")({
  head: () => ({
    meta: [
      { title: "IOC Explorer — MailSentinel AI" },
      {
        name: "description",
        content: "Search, filter and copy indicators of compromise extracted from an analyzed email: IPs, domains, URLs, addresses, hashes and files.",
      },
      { property: "og:title", content: "IOC Explorer — MailSentinel AI" },
      { property: "og:description", content: "Every indicator of compromise extracted from the current investigation." },
    ],
  }),
  component: IocPage,
});

const TYPES: (Ioc["type"] | "All")[] = ["All", "IP", "Domain", "URL", "Email", "Hash", "File"];

function IocPage() {
  const { current } = useInvestigation();
  const [query, setQuery] = useState("");
  const [type, setType] = useState<(typeof TYPES)[number]>("All");

  const rows = useMemo(() => {
    if (!current) return [];
    return current.iocs.filter(
      (i) => (type === "All" || i.type === type) && i.value.toLowerCase().includes(query.trim().toLowerCase()),
    );
  }, [current, query, type]);

  if (!current) {
    return (
      <div className="space-y-6">
        <PageHeader title="IOC Explorer" />
        <EmptyState description="Indicators of compromise appear here after an email has been analyzed." />
      </div>
    );
  }

  const copy = (value: string) =>
    navigator.clipboard?.writeText(value).then(
      () => toast.success("IOC copied to clipboard"),
      () => toast.error("Clipboard is not available in this browser"),
    );

  const copyAll = () => copy(rows.map((r) => `${r.type}\t${r.value}\t${r.reputation}`).join("\n"));

  return (
    <div className="space-y-6">
      <PageHeader
        title="IOC Explorer"
        description={`${current.iocs.length} indicators of compromise extracted from investigation ${current.investigationId}.`}
        action={<DemoTag />}
      />

      <Panel
        title="Extracted Indicators"
        icon={<Radar className="size-4" />}
        action={
          <Button size="sm" variant="outline" onClick={copyAll} disabled={rows.length === 0}>
            <Copy className="size-4" /> Copy All
          </Button>
        }
        bodyClassName="p-0"
      >
        <div className="flex flex-wrap items-center gap-3 border-b border-border/60 px-5 py-4">
          <div className="relative min-w-[220px] flex-1">
            <Search className="absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search IOCs…"
              className="bg-background/60 pl-9"
            />
          </div>
          <div className="flex flex-wrap gap-2">
            {TYPES.map((t) => (
              <button
                key={t}
                onClick={() => setType(t)}
                className={`rounded-full border px-3 py-1 text-xs transition-colors ${
                  type === t ? "border-primary/50 bg-primary/15 text-primary" : "border-border/60 text-muted-foreground hover:text-foreground"
                }`}
              >
                {t}
              </button>
            ))}
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border/60 text-left text-[11px] tracking-[0.12em] text-muted-foreground uppercase">
                <th className="px-5 py-3 font-medium">Type</th>
                <th className="px-5 py-3 font-medium">Value</th>
                <th className="px-5 py-3 font-medium">Reputation</th>
                <th className="px-5 py-3 font-medium">Risk</th>
                <th className="px-5 py-3 font-medium">Source</th>
                <th className="px-5 py-3 font-medium">Action</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((i) => (
                <tr key={`${i.type}-${i.value}`} className="border-b border-border/40 last:border-0">
                  <td className="px-5 py-3">
                    <span className="rounded border border-border/70 px-2 py-0.5 text-[11px] tracking-wide uppercase">{i.type}</span>
                  </td>
                  <td className="max-w-md px-5 py-3 font-mono text-xs break-all">{i.value}</td>
                  <td className="px-5 py-3">
                    <ReputationPill value={i.reputation} />
                  </td>
                  <td className="px-5 py-3">
                    <SeverityPill value={i.risk} />
                  </td>
                  <td className="px-5 py-3 text-xs text-muted-foreground">{i.source}</td>
                  <td className="px-5 py-3">
                    <Button size="sm" variant="ghost" onClick={() => copy(i.value)}>
                      <Copy className="size-3.5" /> Copy
                    </Button>
                  </td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-5 py-8 text-center text-sm text-muted-foreground">
                    No indicators match this filter.
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
