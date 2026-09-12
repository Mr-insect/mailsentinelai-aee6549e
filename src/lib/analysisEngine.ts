import {
  CREDENTIAL_KEYWORDS,
  RISKY_EXTENSIONS,
  SHORTENER_DOMAINS,
  SUSPICIOUS_TLDS,
  URGENCY_KEYWORDS,
  domainOf,
  lookupDomainAgeDays,
  lookupIp,
  looksLikeLookalike,
  registrarFor,
  severityFromScore,
} from "./demoIntel";
import { investigationChecksum } from "./emailParser";
import type {
  AnalysisResult,
  AttachmentIntel,
  AuthCheck,
  AuthStatus,
  DomainIntel,
  Indicator,
  Ioc,
  IpIntel,
  ParsedEmail,
  Reputation,
  Severity,
  TimelineStep,
  UrlIntel,
} from "./types";

/**
 * Explainable, rule-based demo analysis engine.
 * Every score contribution is attached to a visible indicator, so the UI can
 * always explain *why* an email was flagged. This is heuristic demo logic,
 * not a trained machine-learning model.
 */

const WEIGHTS = {
  suspiciousUrl: 25,
  maliciousDomain: 25,
  spfFail: 15,
  dkimFail: 15,
  dmarcFail: 15,
  suspiciousSender: 10,
  credentialLanguage: 15,
  suspiciousAttachment: 20,
  replyToMismatch: 10,
  suspiciousIp: 12,
  urgencyLanguage: 8,
};

function pad(n: number) {
  return String(n).padStart(2, "0");
}

function buildTimeline(base: Date, steps: string[]): TimelineStep[] {
  return steps.map((label, i) => {
    const t = new Date(base.getTime() + i * 1000);
    return {
      time: `${pad(t.getHours())}:${pad(t.getMinutes())}:${pad(t.getSeconds())}`,
      label,
      detail: TIMELINE_DETAILS[label] ?? "Step completed by the analysis engine.",
    };
  });
}

const TIMELINE_DETAILS: Record<string, string> = {
  "Email received": "Message ingested into the analysis pipeline.",
  "Headers parsed": "MIME headers unfolded and normalised.",
  "Sender analyzed": "From, Reply-To and Return-Path compared for alignment.",
  "IP extracted": "Originating hop resolved from the Received chain.",
  "Geolocation identified": "Originating IP mapped with demo geolocation intelligence.",
  "URL analyzed": "Embedded links extracted and scored.",
  "Authentication failure detected": "SPF / DKIM / DMARC verdicts evaluated.",
  "Threat classified": "Weighted rule engine produced a threat category.",
  "Investigation completed": "Findings, IOCs and recommendations compiled.",
};

function authExplain(name: "SPF" | "DKIM" | "DMARC", status: AuthStatus): string {
  const map: Record<string, Record<AuthStatus, string>> = {
    SPF: {
      PASS: "Sending IP is authorized by the domain's SPF record.",
      FAIL: "Sender IP is not authorized by the domain's SPF policy.",
      SUSPICIOUS: "SPF record is missing or returned a neutral result.",
      UNKNOWN: "No SPF result was present in the message headers.",
    },
    DKIM: {
      PASS: "Cryptographic signature verified against the signing domain.",
      FAIL: "Email signature verification failed — body or headers may be altered.",
      SUSPICIOUS: "A DKIM signature exists but no verification result was recorded.",
      UNKNOWN: "No DKIM signature or result was present.",
    },
    DMARC: {
      PASS: "Domain alignment satisfied the published DMARC policy.",
      FAIL: "Domain alignment/authentication policy failed.",
      SUSPICIOUS: "No DMARC policy published for the sending domain.",
      UNKNOWN: "No DMARC result was present in the message headers.",
    },
  };
  return map[name]![status];
}

function analyzeUrls(email: ParsedEmail): UrlIntel[] {
  return email.urls.slice(0, 25).map((url) => {
    const domain = domainOf(url);
    const notes: string[] = [];
    let score = 0;
    const https = url.toLowerCase().startsWith("https://");
    if (!https) {
      notes.push("Link is not encrypted (plain HTTP).");
      score += 15;
    }
    if (SHORTENER_DOMAINS.includes(domain)) {
      notes.push("URL shortening service hides the real destination.");
      score += 30;
    }
    if (SUSPICIOUS_TLDS.some((t) => domain.endsWith(t))) {
      notes.push("Domain uses a top-level domain frequently abused for phishing.");
      score += 25;
    }
    const look = looksLikeLookalike(domain);
    if (look.hit) {
      notes.push(`Domain resembles a legitimate organization${look.brand ? ` ("${look.brand}")` : ""}.`);
      score += 30;
    }
    if (/(login|verify|secure|update|account|password|signin|confirm)/i.test(url)) {
      notes.push("Path contains credential-harvesting keywords.");
      score += 20;
    }
    const redirect = /(redirect|redir=|url=|goto=|next=|r=http)/i.test(url);
    if (redirect) {
      notes.push("Link performs an open redirect to another destination.");
      score += 15;
    }
    if (/\d{1,3}(\.\d{1,3}){3}/.test(domain)) {
      notes.push("Link points directly at a raw IP address.");
      score += 25;
    }
    const capped = Math.min(100, score);
    const reputation: Reputation = capped >= 60 ? "MALICIOUS" : capped >= 30 ? "SUSPICIOUS" : "CLEAN";
    return { url, domain, https, redirect, reputation, risk: severityFromScore(capped), notes };
  });
}

function analyzeAttachments(email: ParsedEmail): AttachmentIntel[] {
  return email.attachments.map((a) => {
    const lower = a.filename.toLowerCase();
    const risky = RISKY_EXTENSIONS.some((e) => lower.endsWith(e));
    const doubleExt = /\.(pdf|doc|xls|jpg|png|txt)\.[a-z0-9]{2,4}$/i.test(lower);
    const macro = /\.(docm|xlsm|pptm)$/i.test(lower);
    const risk: Severity = doubleExt || macro ? "CRITICAL" : risky ? "HIGH" : "LOW";
    const reputation: Reputation = risk === "CRITICAL" ? "MALICIOUS" : risky ? "SUSPICIOUS" : "CLEAN";
    const status = doubleExt
      ? "MALICIOUS — double extension used to disguise an executable"
      : macro
        ? "MALICIOUS — macro-enabled document"
        : risky
          ? "SUSPICIOUS — high-risk file type"
          : "CLEAN — no static indicators found";
    return { ...a, risk, reputation, status };
  });
}

function analyzeDomains(email: ParsedEmail, urls: UrlIntel[]): DomainIntel[] {
  const domains = new Set<string>();
  if (email.from.includes("@")) domains.add(domainOf(email.from));
  if (email.replyTo.includes("@")) domains.add(domainOf(email.replyTo));
  urls.forEach((u) => domains.add(u.domain));
  return Array.from(domains)
    .filter(Boolean)
    .slice(0, 20)
    .map((domain) => {
      const look = looksLikeLookalike(domain);
      const badTld = SUSPICIOUS_TLDS.some((t) => domain.endsWith(t));
      const hostile = look.hit || badTld;
      const ageDays = lookupDomainAgeDays(domain, hostile);
      const reputation: Reputation = hostile ? (ageDays < 30 ? "MALICIOUS" : "SUSPICIOUS") : "CLEAN";
      const risk: Severity = reputation === "MALICIOUS" ? "CRITICAL" : reputation === "SUSPICIOUS" ? "HIGH" : "LOW";
      return {
        domain,
        ageDays,
        registrar: registrarFor(domain),
        dns: hostile ? "A record on shared bulletproof hosting (demo)" : "A / MX records consistent with mail provider (demo)",
        reputation,
        risk,
        lookalike: look.hit,
      };
    });
}

function extractIocs(
  email: ParsedEmail,
  urls: UrlIntel[],
  ips: IpIntel[],
  domains: DomainIntel[],
  attachments: AttachmentIntel[],
): Ioc[] {
  const iocs: Ioc[] = [];
  const push = (i: Ioc) => {
    if (i.value && !iocs.some((x) => x.type === i.type && x.value === i.value)) iocs.push(i);
  };
  ips.forEach((ip) => push({ type: "IP", value: ip.ip, reputation: ip.reputation, risk: ip.risk, source: "Received headers" }));
  domains.forEach((d) => push({ type: "Domain", value: d.domain, reputation: d.reputation, risk: d.risk, source: "Sender / URL extraction" }));
  urls.forEach((u) => push({ type: "URL", value: u.url, reputation: u.reputation, risk: u.risk, source: "Email body" }));
  [email.from, email.replyTo, email.returnPath, email.to].forEach((addr) => {
    if (!addr || !addr.includes("@")) return;
    const d = domains.find((x) => x.domain === domainOf(addr));
    push({
      type: "Email",
      value: addr,
      reputation: d?.reputation ?? "UNKNOWN",
      risk: d?.risk ?? "LOW",
      source: "Message headers",
    });
  });
  attachments.forEach((a) => {
    push({ type: "File", value: a.filename, reputation: a.reputation, risk: a.risk, source: "MIME attachment" });
    if (a.sha256) {
      push({ type: "Hash", value: a.sha256, reputation: a.reputation, risk: a.risk, source: "Attachment SHA-256 (Web Crypto)" });
    }
  });
  return iocs;
}

export function analyzeEmail(email: ParsedEmail, options: { messageSha256?: string } = {}): AnalysisResult {
  const messageSha256 = options.messageSha256 ?? "";
  const bodyText = `${email.subject}\n${email.body}`.toLowerCase();
  const indicators: Indicator[] = [];
  let score = 0;

  const add = (
    id: string,
    name: string,
    detected: boolean,
    weight: number,
    explanation: string,
    icon: string,
    unknown = false,
  ) => {
    indicators.push({
      id,
      name,
      status: unknown ? "UNKNOWN" : detected ? "DETECTED" : "CLEAR",
      explanation,
      weight: detected ? weight : 0,
      icon,
    });
    if (detected) score += weight;
  };

  // --- Authentication -------------------------------------------------
  const auth: AuthCheck[] = (["SPF", "DKIM", "DMARC"] as const).map((name) => {
    const status =
      name === "SPF" ? email.spfHeader : name === "DKIM" ? email.dkimHeader : email.dmarcHeader;
    return { name, status, explanation: authExplain(name, status) };
  });
  add("spf", "SPF authentication", email.spfHeader === "FAIL", WEIGHTS.spfFail, authExplain("SPF", email.spfHeader), "shield");
  add("dkim", "DKIM authentication", email.dkimHeader === "FAIL", WEIGHTS.dkimFail, authExplain("DKIM", email.dkimHeader), "key");
  add("dmarc", "DMARC policy", email.dmarcHeader === "FAIL", WEIGHTS.dmarcFail, authExplain("DMARC", email.dmarcHeader), "scale");

  // --- Sender ---------------------------------------------------------
  const senderDomain = email.from.includes("@") ? domainOf(email.from) : "UNKNOWN";
  const look = looksLikeLookalike(senderDomain);
  const badSenderTld = SUSPICIOUS_TLDS.some((t) => senderDomain.endsWith(t));
  const suspiciousSender = look.hit || badSenderTld || senderDomain === "UNKNOWN";
  add(
    "sender",
    "Suspicious sender domain",
    suspiciousSender,
    WEIGHTS.suspiciousSender,
    suspiciousSender
      ? `Sending domain "${senderDomain}" is newly seen or imitates a known organization.`
      : `Sending domain "${senderDomain}" shows no reputation issues in demo intelligence.`,
    "user",
  );
  const replyToMismatch =
    !!email.replyTo && email.replyTo.toLowerCase() !== email.from.toLowerCase() && domainOf(email.replyTo) !== senderDomain;
  add(
    "replyto",
    "Reply-To mismatch",
    replyToMismatch,
    WEIGHTS.replyToMismatch,
    replyToMismatch
      ? `Replies are redirected to ${email.replyTo}, a different domain from the sender.`
      : "Reply-To is aligned with the sending address.",
    "corner-up-left",
  );

  // --- Content --------------------------------------------------------
  const credHit = CREDENTIAL_KEYWORDS.filter((k) => bodyText.includes(k));
  add(
    "credential",
    "Credential harvesting language",
    credHit.length > 0,
    WEIGHTS.credentialLanguage,
    credHit.length ? `Message asks the recipient to confirm credentials ("${credHit[0]!}").` : "No credential-harvesting phrasing detected.",
    "key-round",
  );
  const urgHit = URGENCY_KEYWORDS.filter((k) => bodyText.includes(k));
  add(
    "urgency",
    "Urgent / social-engineering language",
    urgHit.length > 0,
    WEIGHTS.urgencyLanguage,
    urgHit.length ? `Pressure tactics detected ("${urgHit[0]!}").` : "No urgency or pressure tactics detected.",
    "alarm-clock",
  );

  // --- URLs, domains, attachments, IPs --------------------------------
  const urlAnalysis = analyzeUrls(email);
  const badUrl = urlAnalysis.find((u) => u.reputation !== "CLEAN");
  add(
    "url",
    "Suspicious URL detected",
    !!badUrl,
    WEIGHTS.suspiciousUrl,
    badUrl ? `${badUrl.url} — ${badUrl.notes[0] ?? "flagged by URL heuristics"}` : email.urls.length ? "All extracted links look benign." : "No URLs found in this message.",
    "link",
    email.urls.length === 0,
  );

  const domainAnalysis = analyzeDomains(email, urlAnalysis);
  const badDomain = domainAnalysis.find((d) => d.reputation === "MALICIOUS");
  add(
    "domain",
    "Malicious domain infrastructure",
    !!badDomain,
    WEIGHTS.maliciousDomain,
    badDomain
      ? `${badDomain.domain} was registered ${badDomain.ageDays} days ago and imitates a trusted brand.`
      : "No domain in this message matches malicious infrastructure patterns.",
    "globe",
  );

  const attachments = analyzeAttachments(email);
  const badAttachment = attachments.find((a) => a.risk === "HIGH" || a.risk === "CRITICAL");
  add(
    "attachment",
    "Suspicious attachment",
    !!badAttachment,
    WEIGHTS.suspiciousAttachment,
    badAttachment ? `${badAttachment.filename}: ${badAttachment.status}` : email.attachments.length ? "Attachments show no static risk indicators." : "No attachments present.",
    "paperclip",
    email.attachments.length === 0,
  );

  const hostileContext = suspiciousSender || !!badUrl || !!badAttachment || email.spfHeader === "FAIL";
  const ipAnalysis: IpIntel[] = email.ips.slice(0, 10).map((ip) => lookupIp(ip, hostileContext));
  const badIp = ipAnalysis.find((i) => i.reputation !== "CLEAN");
  add(
    "ip",
    "Suspicious originating IP",
    !!badIp,
    WEIGHTS.suspiciousIp,
    badIp
      ? `${badIp.ip} (${badIp.city}, ${badIp.country}) has an abuse score of ${badIp.abuseScore}/100 in demo intelligence.`
      : email.ips.length
        ? "Originating infrastructure has no abuse reports in demo intelligence."
        : "No public IP addresses were found in the Received chain.",
    "server",
    email.ips.length === 0,
  );

  // Combine raw rule weights into a bounded 0-100 score (never exceeds 100).
  score = Math.min(100, Math.round(100 * (1 - Math.exp(-score / 55))));
  const severity: Severity = score <= 20 ? "SAFE" : severityFromScore(score);

  // --- Classification --------------------------------------------------
  let threatType = "No Threat Detected";
  if (badAttachment) threatType = "Malware Delivery";
  else if (credHit.length && (badUrl || email.spfHeader === "FAIL")) threatType = "Credential Phishing";
  else if (badUrl || badDomain) threatType = "Phishing / Malicious Link";
  else if (score >= 61) threatType = "Suspicious Email";
  else if (score >= 31) threatType = "Spam / Low-Confidence Suspicious";

  const detectedCount = indicators.filter((i) => i.status === "DETECTED").length;
  const knownCount = indicators.filter((i) => i.status !== "UNKNOWN").length || 1;
  const confidence = Math.round((70 + (detectedCount / knownCount) * 28) * 10) / 10;

  const geolocation: IpIntel | null = ipAnalysis.length ? (badIp ?? ipAnalysis[0] ?? null) : null;
  const iocs = extractIocs(email, urlAnalysis, ipAnalysis, domainAnalysis, attachments);

  const recommendations =
    severity === "SAFE" || severity === "LOW"
      ? [
          "No action required — deliver to inbox",
          "Keep the message for 30 days of retention",
          "Add sender domain to the trusted-sender baseline",
        ]
      : [
          "Quarantine Email",
          "Block Malicious Domain",
          "Block Suspicious IP",
          "Search for Similar Emails",
          "Reset Potentially Exposed Credentials",
          "Notify Security Administrator",
          "Add IOC to Blocklist",
        ];

  const now = new Date();
  const timeline = buildTimeline(now, [
    "Email received",
    "Headers parsed",
    "Sender analyzed",
    "IP extracted",
    "Geolocation identified",
    "URL analyzed",
    "Authentication failure detected",
    "Threat classified",
    "Investigation completed",
  ]);

  const chainSeverity: Severity = severity === "SAFE" ? "LOW" : severity;
  const attackChain = [
    { label: "EMAIL", detail: email.subject.slice(0, 46) || "(no subject)", severity: "LOW" as Severity },
    { label: "SENDER", detail: email.from, severity: suspiciousSender ? chainSeverity : ("LOW" as Severity) },
    { label: "DOMAIN", detail: badDomain?.domain ?? senderDomain, severity: badDomain ? chainSeverity : ("LOW" as Severity) },
    { label: "URL", detail: badUrl?.url.slice(0, 46) ?? (email.urls[0]?.slice(0, 46) || "No links"), severity: badUrl ? chainSeverity : ("LOW" as Severity) },
    { label: "EXTERNAL IP", detail: geolocation?.ip ?? "UNKNOWN", severity: badIp ? chainSeverity : ("LOW" as Severity) },
    { label: "GEOLOCATION", detail: geolocation ? `${geolocation.city}, ${geolocation.country}` : "UNKNOWN", severity: badIp ? chainSeverity : ("LOW" as Severity) },
    { label: "THREAT INTEL", detail: `${iocs.length} IOCs correlated`, severity: chainSeverity },
    { label: "VERDICT", detail: `${severity} — ${threatType}`, severity: chainSeverity },
  ];

  const senderAnalysisDomain = domainAnalysis.find((d) => d.domain === senderDomain);

  if (messageSha256) {
    iocs.push({
      type: "Hash",
      value: messageSha256,
      reputation: severity === "SAFE" ? "CLEAN" : "SUSPICIOUS",
      risk: severity === "SAFE" ? "LOW" : severity,
      source: "Message SHA-256 (Web Crypto)",
    });
  }

  return {
    investigationId: `INV-${now.getFullYear()}-${(messageSha256 || investigationChecksum(email.messageId + email.subject)).slice(0, 6).toUpperCase()}`,
    messageSha256,
    analyzedAt: now.toISOString(),
    mode: "DEMO",
    email,
    riskScore: score,
    threatType,
    severity,
    confidence,
    indicators,
    senderAnalysis: {
      email: email.from,
      displayName: email.displayName,
      domain: senderDomain,
      replyTo: email.replyTo || "Not set",
      replyToMismatch,
      domainAge: senderAnalysisDomain ? `${senderAnalysisDomain.ageDays} days` : "UNKNOWN",
      domainReputation: senderAnalysisDomain?.reputation ?? "UNKNOWN",
      authStatus: `SPF ${email.spfHeader} · DKIM ${email.dkimHeader} · DMARC ${email.dmarcHeader}`,
      risk: suspiciousSender ? (severity === "SAFE" ? "MEDIUM" : severity) : "LOW",
      lookalike: look.hit,
      ...(look.brand ? { lookalikeOf: look.brand } : {}),
    },
    authenticationAnalysis: auth,
    urlAnalysis,
    ipAnalysis,
    domainAnalysis,
    geolocation,
    iocs,
    attachments,
    recommendations,
    timeline,
    attackChain,
  };
}
