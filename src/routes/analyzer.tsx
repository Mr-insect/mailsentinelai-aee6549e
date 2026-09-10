import { createFileRoute } from "@tanstack/react-router";
import { useCallback, useEffect, useRef, useState } from "react";
import { AlertTriangle, FileText, Loader2, Mail, Play, Upload } from "lucide-react";
import { toast } from "sonner";
import { PageHeader, Panel } from "@/components/soc/Panel";
import { DemoTag } from "@/components/soc/Pill";
import { AnalysisProgress, ANALYSIS_STEPS } from "@/components/soc/AnalysisProgress";
import { AnalysisResults } from "@/components/soc/AnalysisResults";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { SAMPLE_EMAILS, getSample, type SampleEmail } from "@/lib/sampleEmails";
import { AnalysisError, emailAnalysisService } from "@/services/emailAnalysisService";
import { useInvestigation } from "@/state/investigation-store";

export const Route = createFileRoute("/analyzer")({
  validateSearch: (search: Record<string, unknown>): { demo?: "phishing" | "malware" | "safe" } => {
    const demo = search["demo"];
    return demo === "phishing" || demo === "malware" || demo === "safe" ? { demo } : {};
  },
  head: () => ({
    meta: [
      { title: "Email Threat Analyzer — MailSentinel AI" },
      {
        name: "description",
        content:
          "Upload an .EML file or paste email content to detect phishing, malware, spoofed authentication and malicious infrastructure.",
      },
      { property: "og:title", content: "Email Threat Analyzer — MailSentinel AI" },
      { property: "og:description", content: "Analyze suspicious emails and get an explainable threat verdict in seconds." },
    ],
  }),
  component: AnalyzerPage,
});

function AnalyzerPage() {
  const { demo } = Route.useSearch();
  const { current, setResult } = useInvestigation();
  const [raw, setRaw] = useState("");
  const [fileName, setFileName] = useState<string>("");
  const [dragging, setDragging] = useState(false);
  const [step, setStep] = useState(-1);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const timers = useRef<ReturnType<typeof setTimeout>[]>([]);

  useEffect(() => () => timers.current.forEach(clearTimeout), []);

  const run = useCallback(
    async (content: string, label: string) => {
      timers.current.forEach(clearTimeout);
      timers.current = [];
      setError(null);
      setRunning(true);
      setStep(0);
      setRaw(content);
      setFileName(label);

      for (let i = 1; i <= ANALYSIS_STEPS.length; i++) {
        timers.current.push(setTimeout(() => setStep(i), i * 190));
      }

      try {
        const [analysis] = await Promise.all([
          emailAnalysisService.analyzeRawEmail(content),
          new Promise((r) => timers.current.push(setTimeout(r, ANALYSIS_STEPS.length * 190 + 350))),
        ]);
        setResult(analysis);
        setStep(ANALYSIS_STEPS.length);
        toast.success("ANALYSIS COMPLETE", {
          description: `${analysis.threatType} · risk ${analysis.riskScore}/100`,
        });
      } catch (err) {
        timers.current.forEach(clearTimeout);
        setStep(-1);
        const message = err instanceof AnalysisError ? err.message : "Analysis failed. Please try another email file.";
        setError(message);
        toast.error(message);
      } finally {
        setRunning(false);
      }
    },
    [setResult],
  );

  const runSample = useCallback(
    (sample: SampleEmail) => {
      void run(sample.raw, `${sample.id}-demo.eml`);
    },
    [run],
  );

  const handleFile = useCallback(
    async (file: File) => {
      setError(null);
      try {
        const text = await file.text();
        const name = file.name.toLowerCase();
        if (!name.endsWith(".eml") && !name.endsWith(".txt")) {
          throw new AnalysisError("Invalid email file. Please upload a valid .EML file.");
        }
        await run(text, file.name);
      } catch (err) {
        const message = err instanceof AnalysisError ? err.message : "The file could not be read. Please try another .EML file.";
        setError(message);
        toast.error(message);
      }
    },
    [run],
  );

  // Auto-run when arriving with ?demo=
  const startedRef = useRef(false);
  useEffect(() => {
    if (demo && !startedRef.current) {
      startedRef.current = true;
      runSample(getSample(demo));
    }
  }, [demo, runSample]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Email Threat Analyzer"
        description="Upload an email or analyze a sample to detect phishing, malware, suspicious infrastructure and other threats."
        action={<DemoTag />}
      />

      <div className="grid gap-6 xl:grid-cols-[1.15fr_1fr]">
        <Panel title="Upload Email" icon={<Upload className="size-4" />}>
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragging(false);
              const file = e.dataTransfer.files?.[0];
              if (file) void handleFile(file);
            }}
            className={`grid-scan grid place-items-center rounded-xl border-2 border-dashed px-6 py-12 text-center transition-colors ${
              dragging ? "border-primary bg-primary/10" : "border-border/70 bg-muted/10"
            }`}
          >
            <Mail className={`size-10 ${dragging ? "text-primary" : "text-muted-foreground"}`} />
            <p className="mt-4 text-sm font-medium">Drag &amp; drop your .EML file here</p>
            <p className="mt-1 text-xs text-muted-foreground">Only .EML (or .txt) files up to 8 MB. Nothing leaves your browser.</p>
            <input
              ref={inputRef}
              type="file"
              accept=".eml,.txt,message/rfc822"
              className="hidden"
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) void handleFile(file);
                e.target.value = "";
              }}
            />
            <Button className="mt-5" onClick={() => inputRef.current?.click()} disabled={running}>
              <Upload className="size-4" /> Browse File
            </Button>
            {fileName && <p className="mt-3 font-mono text-xs text-primary">{fileName}</p>}
          </div>

          <div className="mt-5 grid gap-3 sm:grid-cols-3">
            {SAMPLE_EMAILS.map((s) => (
              <button
                key={s.id}
                disabled={running}
                onClick={() => runSample(s)}
                className={`rounded-lg border px-4 py-3 text-left transition-colors disabled:opacity-60 ${
                  s.id === "safe"
                    ? "border-safe/40 bg-safe/10 hover:bg-safe/20"
                    : s.id === "malware"
                      ? "border-warning/40 bg-warning/10 hover:bg-warning/20"
                      : "border-critical/40 bg-critical/10 hover:bg-critical/20"
                }`}
              >
                <p className="text-xs font-semibold tracking-wide uppercase">{s.label}</p>
                <p className="mt-1 text-[11px] text-muted-foreground">{s.description}</p>
              </button>
            ))}
          </div>

          {error && (
            <p className="mt-4 flex items-start gap-2 rounded-lg border border-critical/40 bg-critical/10 px-4 py-3 text-sm text-critical">
              <AlertTriangle className="mt-0.5 size-4 shrink-0" /> {error}
            </p>
          )}
        </Panel>

        <Panel
          title="Paste Email Content"
          icon={<FileText className="size-4" />}
          action={
            <Button size="sm" disabled={running || !raw.trim()} onClick={() => void run(raw, fileName || "pasted-email.eml")}>
              {running ? <Loader2 className="size-4 animate-spin" /> : <Play className="size-4" />} Analyze Email
            </Button>
          }
        >
          <Textarea
            value={raw}
            onChange={(e) => setRaw(e.target.value)}
            spellCheck={false}
            placeholder={"From: sender@example.com\nTo: you@university.edu\nSubject: ...\n\nPaste the full raw email (headers + body) here."}
            className="h-[320px] resize-none bg-background/60 font-mono text-xs"
          />
          <p className="mt-3 text-xs text-muted-foreground">
            Paste the complete raw message including headers. Missing fields are reported as UNKNOWN rather than guessed.
          </p>
        </Panel>
      </div>

      {step >= 0 && <AnalysisProgress step={step} />}

      {current ? (
        <AnalysisResults result={current} />
      ) : (
        step < 0 && (
          <Panel title="Start Your Investigation">
            <p className="text-sm text-muted-foreground">
              No email has been analyzed yet. Drop an .EML file above, paste raw content, or launch one of the three demo
              scenarios to see the full investigation workflow.
            </p>
          </Panel>
        )
      )}
    </div>
  );
}
