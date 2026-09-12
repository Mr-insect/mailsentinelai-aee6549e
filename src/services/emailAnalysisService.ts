import { analyzeEmail } from "@/lib/analysisEngine";
import { EmailParseError, parseEml } from "@/lib/emailParser";
import { hashAttachments, sha256Hex } from "@/lib/hashing";
import type { AnalysisResult, DomainIntel, IpIntel, UrlIntel } from "@/lib/types";

/**
 * SERVICE LAYER
 * -------------
 * Single boundary between the UI and the analysis backend.
 *
 * Today every call is answered by the local demo engine, so the app runs with
 * zero configuration and zero API keys. When a Python/FastAPI backend exists,
 * set VITE_MAILSENTINEL_API_BASE and the same functions will POST to:
 *
 *   POST /api/analyze-email
 *   POST /api/analyze-headers
 *   GET  /api/ip-intelligence
 *   GET  /api/domain-intelligence
 *   GET  /api/url-intelligence
 *
 * Any network failure falls back to the demo engine, so the demo can never break.
 * Secrets stay on the backend — never in this file.
 */

export const API_BASE: string = (import.meta.env["VITE_MAILSENTINEL_API_BASE"] as string | undefined) ?? "";
export const IS_DEMO_MODE = API_BASE === "";

export const API_ROUTES = {
  analyzeEmail: "/api/analyze-email",
  analyzeHeaders: "/api/analyze-headers",
  ipIntelligence: "/api/ip-intelligence",
  domainIntelligence: "/api/domain-intelligence",
  urlIntelligence: "/api/url-intelligence",
} as const;

async function tryBackend<T>(path: string, init?: RequestInit): Promise<T | null> {
  if (!API_BASE) return null;
  try {
    const res = await fetch(`${API_BASE}${path}`, {
      headers: { "Content-Type": "application/json" },
      ...init,
    });
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null; // graceful fallback to demo intelligence
  }
}

export class AnalysisError extends Error {}

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
  /** Analyze raw .eml content (file upload or pasted text). */
  async analyzeRawEmail(raw: string): Promise<AnalysisResult> {
    if (!raw || !raw.trim()) throw new AnalysisError("The email is empty. Paste content or upload an .EML file.");
    const remote = await tryBackend<AnalysisResult>(API_ROUTES.analyzeEmail, {
      method: "POST",
      body: JSON.stringify({ raw }),
    });
    return remote ?? localAnalyze(raw);
  },

  /** Read + analyze an uploaded file. */
  async analyzeFile(file: File): Promise<AnalysisResult> {
    const name = file.name.toLowerCase();
    if (!name.endsWith(".eml") && !name.endsWith(".txt") && !name.endsWith(".msg")) {
      throw new AnalysisError("Invalid email file. Please upload a valid .EML file.");
    }
    if (file.size > 8 * 1024 * 1024) throw new AnalysisError("File is too large. Please upload an .EML under 8 MB.");
    let text = "";
    try {
      text = await file.text();
    } catch {
      throw new AnalysisError("The file could not be read. Please try another .EML file.");
    }
    return this.analyzeRawEmail(text);
  },

  async ipIntelligence(ip: string, fallback: IpIntel[]): Promise<IpIntel | null> {
    const remote = await tryBackend<IpIntel>(`${API_ROUTES.ipIntelligence}?ip=${encodeURIComponent(ip)}`);
    return remote ?? fallback.find((i) => i.ip === ip) ?? null;
  },

  async domainIntelligence(domain: string, fallback: DomainIntel[]): Promise<DomainIntel | null> {
    const remote = await tryBackend<DomainIntel>(`${API_ROUTES.domainIntelligence}?domain=${encodeURIComponent(domain)}`);
    return remote ?? fallback.find((d) => d.domain === domain) ?? null;
  },

  async urlIntelligence(url: string, fallback: UrlIntel[]): Promise<UrlIntel | null> {
    const remote = await tryBackend<UrlIntel>(`${API_ROUTES.urlIntelligence}?url=${encodeURIComponent(url)}`);
    return remote ?? fallback.find((u) => u.url === url) ?? null;
  },
};
