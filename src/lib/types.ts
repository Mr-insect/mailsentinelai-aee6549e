export type Severity = "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type AuthStatus = "PASS" | "FAIL" | "SUSPICIOUS" | "NONE" | "UNKNOWN";
export type Reputation = "CLEAN" | "SUSPICIOUS" | "MALICIOUS" | "UNKNOWN";
export type EvidenceStatus = "confirmed" | "suspicious" | "unknown" | "unavailable";
export type ObservedKind = "observed" | "inferred";

export interface ParsedAttachment {
  filename: string;
  contentType: string;
  sizeLabel: string;
  /** Real SHA-256 (64 hex chars) of the decoded attachment bytes. */
  sha256: string;
  /** Base64 of the decoded attachment bytes, used to compute the digest. */
  payloadBase64?: string;
  /** Decoded byte length of the attachment. */
  sizeBytes?: number;
  /** Content-Disposition value ("attachment" / "inline"). */
  disposition?: string;
  /** True when the MIME part could not be fully decoded. */
  malformed?: boolean;
}

export interface ParsedEmail {
  from: string;
  displayName: string;
  to: string;
  /** Additional recipients from the CC header. */
  cc: string[];
  replyTo: string;
  returnPath: string;
  subject: string;
  date: string;
  messageId: string;
  received: string[];
  headers: { name: string; value: string }[];
  rawHeaders: string;
  /** Best-effort readable body (plain text, or HTML converted to text). */
  body: string;
  /** Decoded text/plain body, when present. */
  textBody: string;
  /** Decoded text/html body, when present. */
  htmlBody: string;
  urls: string[];
  ips: string[];
  /** Email addresses found in headers and body. */
  emails: string[];
  /** Domains derived from URLs and email addresses. */
  domains: string[];
  attachments: ParsedAttachment[];
  spfHeader: AuthStatus;
  dkimHeader: AuthStatus;
  dmarcHeader: AuthStatus;
  /** Non-fatal issues encountered while decoding MIME parts. */
  parseWarnings: string[];
}

export interface Indicator {
  id: string;
  name: string;
  status: "DETECTED" | "CLEAR" | "UNKNOWN";
  explanation: string;
  weight: number;
  icon: string;
}

export interface AuthCheck {
  name: "SPF" | "DKIM" | "DMARC";
  status: AuthStatus;
  explanation: string;
}

export interface UrlIntel {
  url: string;
  domain: string;
  https: boolean;
  redirect: boolean;
  reputation: Reputation;
  risk: Severity;
  notes: string[];
  /** SOC-grade additive fields (backend LIVE mode). */
  normalized?: string;
  indicators?: string[];
  providers?: Record<string, unknown>;
  confidence?: number;
}

export interface IpIntel {
  ip: string;
  reputation: Reputation;
  country: string;
  countryCode: string;
  city: string;
  region: string;
  isp: string;
  asn: string;
  abuseScore: number;
  risk: Severity;
  lat: number;
  lon: number;
  /** SOC-grade additive fields. Coordinates are ALWAYS approximate. */
  continent?: string;
  postal_code?: string;
  accuracy_radius_km?: number | null;
  timezone?: string;
  organization?: string;
  connection_type?: string;
  hosting?: boolean;
  proxy?: boolean;
  vpn?: boolean;
  tor?: boolean;
  anonymizer_type?: string;
  geo_provider?: string;
  providers?: Record<string, unknown>;
  geo?: Record<string, unknown>;
}

export interface DomainIntel {
  domain: string;
  ageDays: number | null;
  registrar: string;
  dns: string;
  reputation: Reputation;
  risk: Severity;
  lookalike: boolean;
  /** SOC-grade additive fields (backend LIVE mode). */
  registrable?: string;
  subdomain?: string;
  punycode?: boolean;
  shortener?: boolean;
  suspicious_tld?: boolean;
  depth?: number;
  lookalike_of?: string | null;
  sender_mismatch?: boolean;
  reply_mismatch?: boolean;
  notes?: string[];
  providers?: Record<string, unknown>;
}

export interface Ioc {
  type: "IP" | "Domain" | "URL" | "Email" | "Hash" | "File";
  value: string;
  reputation: Reputation;
  risk: Severity;
  source: string;
}

export interface TimelineStep {
  time: string;
  label: string;
  detail: string;
  /** Provenance: which raw evidence produced this step. */
  evidenceSource?: string;
}

export interface AttachmentIntel extends ParsedAttachment {
  risk: Severity;
  status: string;
  reputation: Reputation;
  /** SOC-grade additive fields (backend LIVE mode). */
  verdict?: string;
  extension?: string;
  double_extension?: boolean;
  extension_mismatch?: boolean;
  macro_enabled?: boolean;
  is_archive?: boolean;
  vt?: Record<string, unknown>;
  notes?: string[];
}

export interface SenderAnalysis {
  email: string;
  displayName: string;
  domain: string;
  replyTo: string;
  replyToMismatch: boolean;
  domainAge: string;
  domainReputation: Reputation;
  authStatus: string;
  risk: Severity;
  lookalike: boolean;
  lookalikeOf?: string;
}

export interface EvidenceFinding {
  findingId: string;
  category: string;
  title: string;
  severity: Severity;
  confidence: number;
  observedValue: string;
  source: string;
  provider: string;
  evidence: string;
  timestamp?: string | null;
  status: EvidenceStatus;
  observedVsInferred: ObservedKind;
  relatedIoc?: string;
  recordedAt?: string;
}

export interface ScoreBreakdownItem {
  category: string;
  points: number;
  reason: string;
}

export interface ConfidenceBreakdown {
  parserConfidence?: number;
  evidenceConfidence?: number;
  threatIntelConfidence?: number;
  aiConfidence?: number;
  geolocationConfidence?: number;
  finalVerdictConfidence?: number;
}

export interface InvestigationGraph {
  nodes: { id: string; kind: string; label: string; evidence: string }[];
  edges: { from: string; to: string; rel: string }[];
}

export interface AttackChainNode {
  label: string;
  detail: string;
  severity: Severity;
  stage?: string;
  evidence?: string;
  iocs?: string[];
  confidence?: number;
  source?: string;
}

export interface AnalysisResult {
  investigationId: string;
  /** Real SHA-256 of the full raw message bytes (Web Crypto). Empty if unavailable. */
  messageSha256: string;
  analyzedAt: string;
  mode: "DEMO" | "LIVE";
  email: ParsedEmail;
  riskScore: number;
  threatType: string;
  severity: Severity;
  confidence: number;
  indicators: Indicator[];
  senderAnalysis: SenderAnalysis;
  authenticationAnalysis: AuthCheck[];
  urlAnalysis: UrlIntel[];
  ipAnalysis: IpIntel[];
  domainAnalysis: DomainIntel[];
  geolocation: IpIntel | null;
  iocs: Ioc[];
  attachments: AttachmentIntel[];
  recommendations: string[];
  timeline: TimelineStep[];
  attackChain: AttackChainNode[];
  /** SOC-grade additive sections (backend LIVE mode; absent in demo engine). */
  evidence?: EvidenceFinding[];
  scoreBreakdown?: ScoreBreakdownItem[];
  confidenceBreakdown?: ConfidenceBreakdown;
  authForensics?: Record<string, unknown>;
  investigationGraph?: InvestigationGraph;
  aiAssessment?: {
    used: boolean;
    classification?: string;
    executiveSummary?: string;
    confirmedFindings?: string[];
    suspectedFindings?: string[];
    unknowns?: string[];
    attackTechniques?: string[];
    reasoningSummary?: string;
    confidence?: number;
    severity?: Severity;
    recommendedActions?: string[];
  };
  providerHealth?: Record<string, { status: string; configured?: boolean; [k: string]: unknown }>;
}
