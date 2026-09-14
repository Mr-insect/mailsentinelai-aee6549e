/**
 * EMAIL PARSER
 * ------------
 * Normalizes a raw .eml message into the `ParsedEmail` structure used by the
 * analysis engine. MIME decoding primitives live in ./mime.ts.
 *
 * Security: uploaded email content is untrusted data. Nothing here executes
 * attachments, evaluates scripts or active content, opens URLs or performs any
 * network request — content is only decoded for static analysis. Malformed
 * MIME parts are recorded as warnings and skipped instead of throwing.
 *
 * Modularity: the same normalized structure can later be produced by the
 * FastAPI backend without touching analysisEngine.ts.
 */
import type { AuthStatus, ParsedAttachment, ParsedEmail } from "./types";
import {
  bytesToBase64,
  decodeEncodedWords,
  headerValue,
  headerValues,
  htmlToText,
  humanSize,
  parsePart,
  splitHeadersAndBody,
  walkParts,
  type MimePart,
} from "./mime";

const IP_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const URL_RE = /https?:\/\/[^\s"'<>)\]]+/gi;
const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;

const PRIVATE_PREFIXES = ["10.", "127.", "192.168.", "0.", "255."];

function isPublicIp(ip: string) {
  if (PRIVATE_PREFIXES.some((p) => ip.startsWith(p))) return false;
  if (ip.startsWith("172.")) {
    const second = Number(ip.split(".")[1] ?? "0");
    if (second >= 16 && second <= 31) return false;
  }
  return true;
}

/**
 * Short non-cryptographic identifier used ONLY to label an investigation
 * (e.g. INV-2026-AB12CD). This is a checksum, not a hash of evidence —
 * all evidence digests are real SHA-256 values from src/lib/hashing.ts.
 */
export function investigationChecksum(input: string): string {
  let h1 = 0x811c9dc5;
  let h2 = 0x1000193;
  for (let i = 0; i < input.length; i++) {
    h1 = (h1 ^ input.charCodeAt(i)) >>> 0;
    h1 = (h1 * 16777619) >>> 0;
    h2 = (h2 + h1 * (i + 7)) >>> 0;
  }
  return ((h1 ^ h2) >>> 0).toString(16).padStart(8, "0");
}

function parseAddress(value: string): { email: string; displayName: string } {
  if (!value) return { email: "", displayName: "" };
  const decoded = decodeEncodedWords(value);
  const angle = decoded.match(/<([^>]+)>/);
  const email = (angle ? angle[1]! : decoded).trim().replace(/^mailto:/i, "");
  let displayName = angle ? decoded.slice(0, decoded.indexOf("<")).trim() : "";
  displayName = displayName.replace(/^"|"$/g, "").trim();
  return { email, displayName };
}

function parseAddressList(value: string): string[] {
  if (!value) return [];
  const decoded = decodeEncodedWords(value);
  return Array.from(
    new Set(
      decoded
        .split(",")
        .map((chunk) => parseAddress(chunk).email)
        .filter((e) => e.includes("@")),
    ),
  );
}

function authFromResults(results: string, key: string): AuthStatus {
  const re = new RegExp(`${key}\\s*=\\s*([a-z]+)`, "i");
  const m = results.match(re);
  if (!m) return "UNKNOWN";
  const v = m[1]!.toLowerCase();
  if (v === "pass") return "PASS";
  if (v === "fail" || v === "softfail" || v === "permerror" || v === "reject") return "FAIL";
  if (v === "none" || v === "neutral") return "SUSPICIOUS";
  return "UNKNOWN";
}

function domainOfUrl(url: string): string {
  const m = url.match(/^https?:\/\/([^/?#:]+)/i);
  return m ? m[1]!.toLowerCase() : "";
}

function isAttachmentPart(part: MimePart): boolean {
  if (part.children.length) return false;
  if (part.disposition === "attachment") return true;
  if (part.filename) return true;
  return false;
}

interface Collected {
  textBody: string;
  htmlBody: string;
  attachments: ParsedAttachment[];
  warnings: string[];
}

function collect(root: MimePart): Collected {
  const out: Collected = { textBody: "", htmlBody: "", attachments: [], warnings: [] };
  walkParts(root, (part) => {
    try {
      if (part.malformed) {
        out.warnings.push(
          `A ${part.contentType || "MIME"} part could not be fully decoded and was analyzed as raw text.`,
        );
      }
      if (part.children.length) return;

      if (isAttachmentPart(part)) {
        out.attachments.push({
          filename: part.filename || "(unnamed attachment)",
          contentType: part.contentType || "application/octet-stream",
          sizeBytes: part.bytes.length,
          sizeLabel: humanSize(part.bytes.length),
          disposition: part.disposition || "attachment",
          // Real SHA-256 is filled in by hashAttachments() over these bytes.
          sha256: "",
          payloadBase64: bytesToBase64(part.bytes),
          malformed: part.malformed,
        });
        return;
      }

      if (part.contentType === "text/plain" && !out.textBody) out.textBody = part.text;
      else if (part.contentType === "text/html" && !out.htmlBody) out.htmlBody = part.text;
      else if (part.contentType.startsWith("text/") && !out.textBody) out.textBody = part.text;
    } catch {
      out.warnings.push("A MIME part was skipped because it could not be processed.");
    }
  });
  return out;
}

export class EmailParseError extends Error {}

export function parseEml(raw: string): ParsedEmail {
  const text = (raw ?? "").replace(/\r\n/g, "\n").trim();
  if (!text) throw new EmailParseError("The email file is empty.");

  const { headerBlock } = splitHeadersAndBody(text);

  let root: MimePart;
  try {
    root = parsePart(text);
  } catch {
    throw new EmailParseError("Invalid email file. Please upload a valid .EML file.");
  }

  const headers = root.headers.map((h) => ({ name: h.name, value: h.value }));
  const looksLikeEmail = headers.some((h) =>
    ["from", "to", "subject", "message-id", "received", "date"].includes(h.name.toLowerCase()),
  );
  if (!looksLikeEmail) {
    throw new EmailParseError("Invalid email file. Please upload a valid .EML file.");
  }

  const { textBody, htmlBody, attachments, warnings } = collect(root);
  const bodyForAnalysis = textBody || (htmlBody ? htmlToText(htmlBody) : "");

  const { email: from, displayName } = parseAddress(headerValue(root.headers, "From"));
  const replyTo = parseAddress(headerValue(root.headers, "Reply-To")).email;
  const returnPath = parseAddress(headerValue(root.headers, "Return-Path")).email;
  const cc = parseAddressList(headerValue(root.headers, "Cc"));
  const received = headerValues(root.headers, "Received");
  const authResults = [
    ...headerValues(root.headers, "Authentication-Results"),
    ...headerValues(root.headers, "ARC-Authentication-Results"),
  ].join(" ");

  // Indicators — links from decoded plain text plus HTML href/src attributes.
  const hrefs = Array.from(htmlBody.matchAll(/(?:href|src)\s*=\s*["']([^"']+)["']/gi)).map((m) => m[1]!);
  const urlSource = [textBody, htmlBody, hrefs.join(" ")].join("\n");
  const urls = Array.from(new Set((urlSource.match(URL_RE) ?? []).map((u) => u.replace(/[.,;)]+$/, ""))));

  const ipsSource = [...received, headerBlock].join(" ");
  const ips = Array.from(new Set((ipsSource.match(IP_RE) ?? []).filter(isPublicIp)));

  const emails = Array.from(
    new Set(
      [
        from,
        replyTo,
        returnPath,
        ...cc,
        ...parseAddressList(headerValue(root.headers, "To")),
        ...((bodyForAnalysis.match(EMAIL_RE) ?? []) as string[]),
      ]
        .filter((e) => e && e.includes("@"))
        .map((e) => e.toLowerCase()),
    ),
  );

  const domains = Array.from(
    new Set(
      [...urls.map(domainOfUrl), ...emails.map((e) => e.split("@")[1] ?? "")].filter(Boolean).map((d) => d.toLowerCase()),
    ),
  );

  const spfDirect = headerValue(root.headers, "Received-SPF");
  const spf: AuthStatus = authResults
    ? authFromResults(authResults, "spf")
    : spfDirect
      ? /pass/i.test(spfDirect)
        ? "PASS"
        : "FAIL"
      : "UNKNOWN";

  return {
    from: from || "UNKNOWN",
    displayName: displayName || "UNKNOWN",
    to: parseAddress(headerValue(root.headers, "To")).email || "UNKNOWN",
    cc,
    replyTo: replyTo || "",
    returnPath: returnPath || "",
    subject: decodeEncodedWords(headerValue(root.headers, "Subject")) || "(no subject)",
    date: headerValue(root.headers, "Date") || "UNKNOWN",
    messageId: headerValue(root.headers, "Message-ID") || "UNKNOWN",
    received,
    headers,
    rawHeaders: headerBlock,
    body: bodyForAnalysis,
    textBody,
    htmlBody,
    urls,
    ips,
    emails,
    domains,
    attachments,
    spfHeader: spf,
    dkimHeader: authResults
      ? authFromResults(authResults, "dkim")
      : headerValue(root.headers, "DKIM-Signature")
        ? "SUSPICIOUS"
        : "UNKNOWN",
    dmarcHeader: authResults ? authFromResults(authResults, "dmarc") : "UNKNOWN",
    parseWarnings: Array.from(new Set(warnings)),
  };
}
