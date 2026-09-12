export type Severity = "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type AuthStatus = "PASS" | "FAIL" | "SUSPICIOUS" | "UNKNOWN";
export type Reputation = "CLEAN" | "SUSPICIOUS" | "MALICIOUS" | "UNKNOWN";

export interface ParsedAttachment {
  filename: string;
  contentType: string;
  sizeLabel: string;
  /** Real SHA-256 (64 hex chars) of the decoded attachment bytes. */
  sha256: string;
  /** Raw base64 MIME payload, used to compute the digest. */
  payloadBase64?: string;
}

export interface ParsedEmail {
  from: string;
  displayName: string;
  to: string;
  replyTo: string;
  returnPath: string;
  subject: string;
  date: string;
  messageId: string;
  received: string[];
  headers: { name: string; value: string }[];
  rawHeaders: string;
  body: string;
  urls: string[];
  ips: string[];
  attachments: ParsedAttachment[];
  spfHeader: AuthStatus;
  dkimHeader: AuthStatus;
  dmarcHeader: AuthStatus;
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
}

export interface DomainIntel {
  domain: string;
  ageDays: number | null;
  registrar: string;
  dns: string;
  reputation: Reputation;
  risk: Severity;
  lookalike: boolean;
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
}

export interface AttachmentIntel extends ParsedAttachment {
  risk: Severity;
  status: string;
  reputation: Reputation;
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

export interface AnalysisResult {
  investigationId: string;
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
  attackChain: { label: string; detail: string; severity: Severity }[];
}
