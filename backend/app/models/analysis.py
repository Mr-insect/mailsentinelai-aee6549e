"""Pydantic models mirroring the frontend AnalysisResult contract (src/lib/types.ts).

The frontend renders exactly this shape; the backend must never break it.
Providers return partial intel which is merged here into the normalized form.
"""
from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
AuthStatus = Literal["PASS", "FAIL", "SUSPICIOUS", "UNKNOWN", "NONE"]
Reputation = Literal["CLEAN", "SUSPICIOUS", "MALICIOUS", "UNKNOWN"]
EvidenceStatus = Literal["confirmed", "suspicious", "unknown", "unavailable"]
ObservedKind = Literal["observed", "inferred"]


class ParsedAttachment(BaseModel):
    filename: str = ""
    contentType: str = ""
    sizeLabel: str = "0 B"
    sha256: str = ""
    sizeBytes: int = 0
    disposition: str = ""
    malformed: bool = False


class ParsedEmail(BaseModel):
    from_: str = Field(default="UNKNOWN", alias="from")
    displayName: str = "UNKNOWN"
    to: str = "UNKNOWN"
    cc: list[str] = []
    replyTo: str = ""
    returnPath: str = ""
    subject: str = "(no subject)"
    date: str = "UNKNOWN"
    messageId: str = "UNKNOWN"
    received: list[str] = []
    headers: list[dict[str, str]] = []
    rawHeaders: str = ""
    body: str = ""
    textBody: str = ""
    htmlBody: str = ""
    urls: list[str] = []
    ips: list[str] = []
    emails: list[str] = []
    domains: list[str] = []
    attachments: list[ParsedAttachment] = []
    spfHeader: AuthStatus = "UNKNOWN"
    dkimHeader: AuthStatus = "UNKNOWN"
    dmarcHeader: AuthStatus = "UNKNOWN"
    parseWarnings: list[str] = []

    model_config = {"populate_by_name": True}


class Indicator(BaseModel):
    id: str
    name: str
    status: Literal["DETECTED", "CLEAR", "UNKNOWN"] = "UNKNOWN"
    explanation: str = ""
    weight: int = 0
    icon: str = "shield"


class AuthCheck(BaseModel):
    name: Literal["SPF", "DKIM", "DMARC"]
    status: AuthStatus = "UNKNOWN"
    explanation: str = ""


class UrlIntel(BaseModel):
    url: str
    domain: str = ""
    https: bool = True
    redirect: bool = False
    reputation: Reputation = "UNKNOWN"
    risk: Severity = "LOW"
    notes: list[str] = []
    # Phase 5 additions (optional, backward compatible)
    normalized: str = ""
    indicators: list[str] = []
    providers: dict = {}
    confidence: int = 50


class IpIntel(BaseModel):
    ip: str
    reputation: Reputation = "UNKNOWN"
    country: str = "UNKNOWN"
    countryCode: str = "--"
    city: str = "UNKNOWN"
    region: str = "UNKNOWN"
    isp: str = "UNKNOWN"
    asn: str = "UNKNOWN"
    abuseScore: int = 0
    risk: Severity = "LOW"
    lat: float = 0.0
    lon: float = 0.0
    # Phase 2/3 additions (optional)
    continent: str = "UNKNOWN"
    postal_code: str = ""
    accuracy_radius_km: int | None = None
    timezone: str = "UNKNOWN"
    organization: str = "UNKNOWN"
    connection_type: str = "UNKNOWN"
    hosting: bool = False
    proxy: bool = False
    vpn: bool = False
    tor: bool = False
    anonymizer_type: str = ""
    geo_provider: str = ""
    providers: dict = {}
    geo: dict = {}


class DomainIntel(BaseModel):
    domain: str
    ageDays: int | None = None
    registrar: str = "UNKNOWN"
    dns: str = "UNKNOWN"
    reputation: Reputation = "UNKNOWN"
    risk: Severity = "LOW"
    lookalike: bool = False
    # Phase 4 additions (optional)
    registrable: str = ""
    subdomain: str = ""
    punycode: bool = False
    shortener: bool = False
    suspicious_tld: bool = False
    depth: int = 0
    lookalike_of: str | None = None
    sender_mismatch: bool = False
    reply_mismatch: bool = False
    notes: list[str] = []
    providers: dict = {}
    # Real DNS intelligence (additive; old frontends ignore unknown keys).
    dnsStatus: str = "UNKNOWN"   # OK | NXDOMAIN | UNKNOWN
    dnssec: str = "UNKNOWN"      # SIGNED | UNSIGNED | UNKNOWN
    dnsRecords: dict = {}        # {"a": [...], "aaaa": [...], "mx": ..., "ns": ..., "txt": ..., "cname": ..., "ptr": [...]}
    dnsLookups: dict = {}        # per-type query state: FOUND | MISSING | ERROR
    resolvedIps: list[str] = []


class Ioc(BaseModel):
    type: Literal["IP", "Domain", "URL", "Email", "Hash", "File"]
    value: str
    reputation: Reputation = "UNKNOWN"
    risk: Severity = "LOW"
    source: str = ""


class TimelineStep(BaseModel):
    time: str
    label: str
    detail: str
    evidence_source: str = ""


class AttachmentIntel(ParsedAttachment):
    risk: Severity = "LOW"
    status: str = "Clean"
    reputation: Reputation = "CLEAN"
    # Phase 8 additions (optional)
    verdict: str = "UNKNOWN"
    extension: str = ""
    double_extension: bool = False
    extension_mismatch: bool = False
    macro_enabled: bool = False
    is_archive: bool = False
    vt: dict = {}
    notes: list[str] = []


class SenderAnalysis(BaseModel):
    email: str = "UNKNOWN"
    displayName: str = "UNKNOWN"
    domain: str = "UNKNOWN"
    replyTo: str = "Not set"
    replyToMismatch: bool = False
    domainAge: str = "UNKNOWN"
    domainReputation: Reputation = "UNKNOWN"
    authStatus: str = ""
    risk: Severity = "LOW"
    lookalike: bool = False
    lookalikeOf: str | None = None


class AttackNode(BaseModel):
    label: str
    detail: str
    severity: Severity = "LOW"
    # Phase 9 additions (optional)
    stage: str = ""
    evidence: str = ""
    iocs: list[str] = []
    confidence: int = 50
    source: str = ""


class EvidenceFinding(BaseModel):
    finding_id: str = ""
    category: str = ""
    title: str = ""
    severity: Severity = "LOW"
    confidence: int = 50
    observed_value: str = ""
    source: str = ""
    provider: str = ""
    evidence: str = ""
    timestamp: str | None = None
    status: EvidenceStatus = "unknown"
    observed_vs_inferred: ObservedKind = "observed"
    related_ioc: str = ""
    recorded_at: str = ""


class ScoreBreakdownItem(BaseModel):
    category: str = ""
    points: int = 0
    reason: str = ""


class ConfidenceBreakdown(BaseModel):
    parser_confidence: int = 70
    evidence_confidence: int = 50
    threat_intel_confidence: int = 30
    ai_confidence: int = 0
    geolocation_confidence: int = 20
    final_verdict_confidence: int = 50


class InvestigationGraph(BaseModel):
    nodes: list[dict] = []
    edges: list[dict] = []


class AnalysisResult(BaseModel):
    investigationId: str
    messageSha256: str = ""
    analyzedAt: str
    mode: Literal["DEMO", "LIVE"] = "LIVE"
    email: ParsedEmail
    riskScore: int = 0
    threatType: str = "Unknown"
    severity: Severity = "LOW"
    confidence: int = 50
    indicators: list[Indicator] = []
    senderAnalysis: SenderAnalysis
    authenticationAnalysis: list[AuthCheck] = []
    urlAnalysis: list[UrlIntel] = []
    ipAnalysis: list[IpIntel] = []
    domainAnalysis: list[DomainIntel] = []
    geolocation: IpIntel | None = None
    iocs: list[Ioc] = []
    attachments: list[AttachmentIntel] = []
    recommendations: list[str] = []
    timeline: list[TimelineStep] = []
    attackChain: list[AttackNode] = []
    # SOC-grade additive sections (all optional; old frontends ignore them)
    evidence: list[EvidenceFinding] = []
    scoreBreakdown: list[ScoreBreakdownItem] = []
    confidenceBreakdown: ConfidenceBreakdown | None = None
    authForensics: dict = {}
    investigationGraph: InvestigationGraph | None = None
    aiAssessment: dict = {}
    providerHealth: dict = {}


class AiVerdict(BaseModel):
    """Structured output requested from the REAL AI model (analyst assistant)."""

    threat_type: str = "Suspicious Email"
    risk_score: int = 50
    severity: Severity = "MEDIUM"
    confidence: int = 60
    summary: str = ""
    reasons: list[str] = []
    recommended_actions: list[str] = []
    # Phase 10 structured analyst output (optional)
    classification: str = ""
    executive_summary: str = ""
    confirmed_findings: list[str] = []
    suspected_findings: list[str] = []
    unknowns: list[str] = []
    attack_techniques: list[str] = []
    reasoning_summary: str = ""
