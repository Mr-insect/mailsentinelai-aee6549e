import { analyzeEmail } from "@/lib/analysisEngine";
import { EmailParseError, parseEml } from "@/lib/emailParser";
import { hashAttachments, sha256Hex } from "@/lib/hashing";
import type { AnalysisResult, DomainIntel, IpIntel, UrlIntel } from "@/lib/types";

/**
 * SERVICE LAYER — frontend calls the FastAPI backend only.
 * Security: no API keys here or in VITE_* vars. Provider keys stay
 * in backend server env. Browser sends EML bytes; backend returns
 * a normalized AnalysisResult with no secrets. Offline engine is
 * the fallback so the UI never breaks.
 */

export const API_BASE: string =
  ((import.meta.env["VITE_MAILSENTINEL_API_BASE"] as string | undefined) ?? "").replace(/\/$/, "");
export const IS_DEMO_MODE = API_BASE === "";

export const API_ROUTES = {
  analyzeEmail: "/api/analyze-email",
  analyzeRaw: "/api/analyze-raw",
  analyzeHeaders: "/api/analyze-headers",
  ipIntelligence: "/api/analyze-ip",
  domainIntelligence: "/api/analyze-domain",
  urlIntelligence: "/api/analyze-url",
  health: "/api/health",
  providerHealth: "/api/health/providers",
} as const;

async function postFile<T>(path: string, file: File): Promise<T> {
  const form = new FormData();
  form.append("file", file, file.name);
  const res = await fetch(`${API_BASE}${path}`, { method: "POST", body: form });
  if (!res.ok) throw new Error(`Backend ${res.status}`);
  return (await res.json()) as T;
}

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`Backend ${res.status}`);
  return (await res.json()) as T;
}

export class AnalysisError extends Error {}

/** Sanitized provider health status from GET /api/health/providers. */
export interface ProviderHealthStatus {
  status: "CONNECTED" | "DISABLED" | "RATE_LIMITED" | "ERROR" | "TIMEOUT" | "NOT_CONFIGURED";
  configured?: boolean;
  provider?: string;
  model?: string;
  note?: string;
}

async function localAnalyze(raw: string, bytes?: ArrayBuffer): Promise<AnalysisResult> {
  try {
    const parsed = parseEml(raw);
    // Real SHA-256 (Web Crypto) of the original file bytes when available,
    // otherwise of the raw message text. Modular: this call can be moved to
    // a FastAPI endpoint without touching the analysis engine.
    let messageSha256 = "";
    try {
      messageSha256 = await sha256Hex(bytes ?? raw);
      await hashAttachments(parsed.attachments);
    } catch {
      messageSha256 = "";
    }
    return analyzeEmail(parsed, { messageSha256 });
  } catch (err) {
    if (err instanceof EmailParseError) throw new AnalysisError(err.message);
    throw new AnalysisError("Analysis failed. The message could not be processed.");
  }
}

export const emailAnalysisService = {
  /** Analyze raw .eml content (pasted text or demo samples) via backend, else offline. */
  async analyzeRawEmail(raw: string, fileBytes?: ArrayBuffer): Promise<AnalysisResult> {
    if (!raw || !raw.trim()) throw new AnalysisError("The email is empty. Paste content or upload an .EML file.");
    if (API_BASE) {
      try {
        return (await postJson<AnalysisResult>(API_ROUTES.analyzeRaw, { raw })) as AnalysisResult;
      } catch {
        // fall through to offline engine
      }
    }
    return localAnalyze(raw, fileBytes);
  },

  /** Upload file bytes to backend (multipart), else parse locally. */
  async analyzeFile(file: File): Promise<AnalysisResult> {
    const name = file.name.toLowerCase();
    if (!name.endsWith(".eml") && !name.endsWith(".txt") && !name.endsWith(".msg")) {
      throw new AnalysisError("Invalid email file. Please upload a valid .EML file.");
    }
    if (file.size > 8 * 1024 * 1024) throw new AnalysisError("File is too large. Please upload an .EML under 8 MB.");
    if (API_BASE) {
      try {
        return (await postFile<AnalysisResult>(API_ROUTES.analyzeEmail, file)) as AnalysisResult;
      } catch {
        // fall through and read locally
      }
    }
    let text = "";
    let bytes: ArrayBuffer | undefined;
    try {
      bytes = await file.arrayBuffer();
      text = new TextDecoder().decode(bytes);
    } catch {
      throw new AnalysisError("The file could not be read. Please try another .EML file.");
    }
    return this.analyzeRawEmail(text, bytes);
  },

  async health(): Promise<{ status: string; service: string } | null> {
    if (!API_BASE) return null;
    try {
      const res = await fetch(`${API_BASE}${API_ROUTES.health}`);
      if (!res.ok) return null;
      return (await res.json()) as { status: string; service: string };
    } catch {
      return null;
    }
  },

  /** Sanitized provider status (Phase 17). No secrets are ever returned. */
  async providerHealth(): Promise<Record<string, ProviderHealthStatus> | null> {
    if (!API_BASE) return null;
    try {
      const res = await fetch(`${API_BASE}${API_ROUTES.providerHealth}`);
      if (!res.ok) return null;
      const body = (await res.json()) as { providers?: Record<string, ProviderHealthStatus> };
      return body.providers ?? null;
    } catch {
      return null;
    }
  },

  async ipIntelligence(ip: string, fallback: IpIntel[]): Promise<IpIntel | null> {
    if (API_BASE) {
      try {
        const remote = await postJson<IpIntel>(API_ROUTES.ipIntelligence, { value: ip });
        if (remote && typeof remote === "object" && "ip" in remote) return remote;
      } catch {
        // fallback below
      }
    }
    return fallback.find((i) => i.ip === ip) ?? null;
  },

  async domainIntelligence(domain: string, fallback: DomainIntel[]): Promise<DomainIntel | null> {
    if (API_BASE) {
      try {
        const remote = await postJson<DomainIntel>(API_ROUTES.domainIntelligence, { value: domain });
        if (remote && typeof remote === "object") return remote;
      } catch {
        // fallback below
      }
    }
    return fallback.find((d) => d.domain === domain) ?? null;
  },

  async urlIntelligence(url: string, fallback: UrlIntel[]): Promise<UrlIntel | null> {
    if (API_BASE) {
      try {
        const remote = await postJson<UrlIntel>(API_ROUTES.urlIntelligence, { value: url });
        if (remote && typeof remote === "object" && "url" in remote) return remote;
      } catch {
        // fallback below
      }
    }
    return fallback.find((u) => u.url === url) ?? null;
  },
};
