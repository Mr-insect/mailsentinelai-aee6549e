import type { IpIntel, Reputation, Severity } from "./types";

/**
 * DEMO INTELLIGENCE LAYER
 * -----------------------
 * Deterministic, offline, fabricated-for-demo data. No external API is called.
 * When a real threat-intel backend is connected, replace these lookups with
 * calls made from the service layer (see src/services/emailAnalysisService.ts).
 */

export const LOOKALIKE_BRANDS = [
  "university",
  "microsoft",
  "office365",
  "paypal",
  "google",
  "apple",
  "amazon",
  "netflix",
  "dhl",
  "bank",
];

export const SUSPICIOUS_TLDS = [".zip", ".top", ".xyz", ".click", ".link", ".tk", ".ru", ".cn", ".gq", ".rest"];

export const SHORTENER_DOMAINS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly"];

export const CREDENTIAL_KEYWORDS = [
  "verify your account",
  "confirm your password",
  "login to continue",
  "sign in to verify",
  "update your credentials",
  "account will be suspended",
  "reset your password",
  "validate your account",
  "confirm your identity",
];

export const URGENCY_KEYWORDS = [
  "urgent",
  "immediately",
  "within 24 hours",
  "final notice",
  "action required",
  "failure to comply",
  "suspended",
  "last warning",
  "act now",
];

export const RISKY_EXTENSIONS = [".exe", ".js", ".vbs", ".scr", ".jar", ".iso", ".bat", ".cmd", ".docm", ".xlsm", ".htm", ".html", ".zip", ".rar", ".7z"];

const GEO_POOL: Omit<IpIntel, "ip" | "reputation" | "risk" | "abuseScore">[] = [
  { country: "Netherlands", countryCode: "NL", city: "Amsterdam", region: "North Holland", isp: "Example Hosting B.V.", asn: "AS64512", lat: 52.3676, lon: 4.9041 },
  { country: "Russia", countryCode: "RU", city: "Saint Petersburg", region: "Leningrad Oblast", isp: "Demo Transit Networks", asn: "AS64513", lat: 59.9311, lon: 30.3609 },
  { country: "Nigeria", countryCode: "NG", city: "Lagos", region: "Lagos State", isp: "Sample Broadband Ltd", asn: "AS64514", lat: 6.5244, lon: 3.3792 },
  { country: "United States", countryCode: "US", city: "Ashburn", region: "Virginia", isp: "Example Cloud Services", asn: "AS64515", lat: 39.0438, lon: -77.4874 },
  { country: "India", countryCode: "IN", city: "Mumbai", region: "Maharashtra", isp: "Demo Datacenter Pvt Ltd", asn: "AS64516", lat: 19.076, lon: 72.8777 },
  { country: "Germany", countryCode: "DE", city: "Frankfurt", region: "Hesse", isp: "Sample Colo GmbH", asn: "AS64517", lat: 50.1109, lon: 8.6821 },
  { country: "Singapore", countryCode: "SG", city: "Singapore", region: "Central", isp: "Example Asia Networks", asn: "AS64518", lat: 1.3521, lon: 103.8198 },
  { country: "Brazil", countryCode: "BR", city: "São Paulo", region: "São Paulo", isp: "Demo Telecom SA", asn: "AS64519", lat: -23.5505, lon: -46.6333 },
];

function hashNum(value: string): number {
  let h = 2166136261;
  for (let i = 0; i < value.length; i++) {
    h ^= value.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return Math.abs(h);
}

export function severityFromScore(score: number): Severity {
  if (score >= 81) return "CRITICAL";
  if (score >= 61) return "HIGH";
  if (score >= 31) return "MEDIUM";
  return "LOW";
}

/** Offline geolocation + reputation lookup. Deterministic per IP. */
export function lookupIp(ip: string, hostile: boolean): IpIntel {
  const h = hashNum(ip);
  const geo = GEO_POOL[h % GEO_POOL.length];
  const abuseScore = hostile ? 55 + (h % 45) : h % 22;
  const reputation: Reputation = abuseScore >= 75 ? "MALICIOUS" : abuseScore >= 40 ? "SUSPICIOUS" : "CLEAN";
  const risk: Severity = abuseScore >= 75 ? "CRITICAL" : abuseScore >= 40 ? "HIGH" : abuseScore >= 20 ? "MEDIUM" : "LOW";
  return { ip, ...geo, abuseScore, reputation, risk };
}

export function domainOf(value: string): string {
  try {
    if (value.includes("@")) return value.split("@").pop()!.toLowerCase();
    return new URL(value).hostname.toLowerCase();
  } catch {
    return value.toLowerCase();
  }
}

export function lookupDomainAgeDays(domain: string, hostile: boolean): number {
  const h = hashNum(domain);
  return hostile ? 1 + (h % 45) : 900 + (h % 5000);
}

export const REGISTRARS = [
  "Demo Registrar LLC",
  "Example Domains Inc.",
  "Sample Name Services",
  "Placeholder Registry Ltd",
];

export function registrarFor(domain: string) {
  return REGISTRARS[hashNum(domain) % REGISTRARS.length];
}

export function looksLikeLookalike(domain: string): { hit: boolean; brand?: string } {
  const bare = domain.replace(/^www\./, "");
  const label = bare.split(".")[0];
  for (const brand of LOOKALIKE_BRANDS) {
    if (bare.includes(brand) && !bare.endsWith(`${brand}.com`) && !bare.endsWith(".edu")) {
      return { hit: true, brand };
    }
    if (label.replace(/[-_0-9]/g, "").includes(brand)) return { hit: true, brand };
  }
  if (/-(secure|login|verify|account|support|update)\b/.test(bare)) return { hit: true, brand: bare.split("-")[0] };
  return { hit: false };
}
