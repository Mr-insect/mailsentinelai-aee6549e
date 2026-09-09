import { Link, useRouterState } from "@tanstack/react-router";
import {
  Fingerprint,
  Globe2,
  LayoutDashboard,
  MailSearch,
  Menu,
  Radar,
  ScrollText,
  Settings,
  ShieldAlert,
  X,
} from "lucide-react";
import { useState, type ReactNode } from "react";
import { cn } from "@/lib/utils";

const NAV = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/analyzer", label: "Email Analyzer", icon: MailSearch },
  { to: "/threat-intelligence", label: "Threat Intelligence", icon: ShieldAlert },
  { to: "/geolocation", label: "Geolocation", icon: Globe2 },
  { to: "/forensics", label: "Forensic Investigation", icon: Fingerprint },
  { to: "/ioc", label: "IOC Explorer", icon: Radar },
  { to: "/reports", label: "Reports", icon: ScrollText },
  { to: "/settings", label: "Settings", icon: Settings },
] as const;

export function AppShell({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const pathname = useRouterState({ select: (s) => s.location.pathname });

  return (
    <div className="flex min-h-screen">
      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-40 flex w-64 flex-col border-r border-sidebar-border bg-sidebar/95 backdrop-blur-xl transition-transform lg:translate-x-0",
          open ? "translate-x-0" : "-translate-x-full",
        )}
      >
        <div className="flex items-center gap-3 border-b border-sidebar-border px-5 py-5">
          <span className="grid size-10 place-items-center rounded-xl border border-primary/40 bg-primary/10 text-primary">
            <ShieldAlert className="size-5" />
          </span>
          <div>
            <p className="text-sm font-semibold tracking-tight">MailSentinel AI</p>
            <p className="text-[10px] tracking-[0.16em] text-muted-foreground uppercase">Threat Detection</p>
          </div>
          <button className="ml-auto text-muted-foreground lg:hidden" onClick={() => setOpen(false)} aria-label="Close navigation">
            <X className="size-5" />
          </button>
        </div>

        <nav className="flex-1 space-y-1 overflow-y-auto px-3 py-4">
          {NAV.map((item) => {
            const active = item.to === "/" ? pathname === "/" : pathname.startsWith(item.to);
            const Icon = item.icon;
            return (
              <Link
                key={item.to}
                to={item.to}
                onClick={() => setOpen(false)}
                className={cn(
                  "flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition-colors",
                  active
                    ? "border border-primary/25 bg-primary/12 text-primary"
                    : "text-sidebar-foreground/80 hover:bg-sidebar-accent hover:text-sidebar-accent-foreground",
                )}
              >
                <Icon className="size-4 shrink-0" />
                {item.label}
              </Link>
            );
          })}
        </nav>

        <div className="space-y-2 border-t border-sidebar-border px-5 py-4 text-xs">
          <p className="flex items-center gap-2 font-medium text-safe">
            <span className="size-2 animate-pulse-dot rounded-full bg-safe" /> SYSTEM ONLINE
          </p>
          <p className="inline-flex rounded-md border border-primary/30 bg-primary/10 px-2 py-0.5 text-[10px] tracking-[0.16em] text-primary uppercase">
            Demo Mode
          </p>
        </div>
      </aside>

      {open && <div className="fixed inset-0 z-30 bg-black/60 lg:hidden" onClick={() => setOpen(false)} />}

      <div className="flex min-w-0 flex-1 flex-col lg:pl-64">
        <header className="sticky top-0 z-20 flex items-center gap-3 border-b border-border/60 bg-background/80 px-4 py-3 backdrop-blur-xl lg:px-8">
          <button className="text-muted-foreground lg:hidden" onClick={() => setOpen(true)} aria-label="Open navigation">
            <Menu className="size-5" />
          </button>
          <div className="min-w-0">
            <p className="truncate text-xs tracking-[0.18em] text-muted-foreground uppercase">
              Security Operations Center
            </p>
            <p className="truncate text-sm font-medium">
              AI-Powered Email Threat Detection, Geolocation &amp; Forensic Intelligence
            </p>
          </div>
          <span className="ml-auto hidden items-center gap-2 rounded-full border border-safe/30 bg-safe/10 px-3 py-1 text-[11px] font-semibold tracking-wider text-safe uppercase sm:inline-flex">
            <span className="size-1.5 animate-pulse-dot rounded-full bg-safe" /> Live
          </span>
        </header>
        <main className="flex-1 px-4 py-6 lg:px-8 lg:py-8">{children}</main>
      </div>
    </div>
  );
}
