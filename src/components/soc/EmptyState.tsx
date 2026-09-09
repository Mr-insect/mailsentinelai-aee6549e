import { Link } from "@tanstack/react-router";
import { Radar, Upload } from "lucide-react";
import { Button } from "@/components/ui/button";

export function EmptyState({
  title = "Start Your Investigation",
  description = "No email has been analyzed yet. Upload an .EML file or launch a demo investigation to populate this page.",
}: {
  title?: string;
  description?: string;
}) {
  return (
    <div className="glass grid-scan animate-rise grid place-items-center rounded-xl px-6 py-16 text-center">
      <div className="grid size-16 place-items-center rounded-2xl border border-primary/30 bg-primary/10 text-primary">
        <Radar className="size-8 animate-pulse-dot" />
      </div>
      <h2 className="mt-5 text-xl font-semibold">{title}</h2>
      <p className="mt-2 max-w-md text-sm text-muted-foreground">{description}</p>
      <div className="mt-6 flex flex-wrap justify-center gap-3">
        <Button asChild>
          <Link to="/analyzer">
            <Upload className="size-4" /> Upload .EML
          </Link>
        </Button>
        <Button asChild variant="outline">
          <Link to="/analyzer" search={{ demo: "phishing" }}>
            Try Demo Investigation
          </Link>
        </Button>
      </div>
    </div>
  );
}
