import type { AuthStatus, ParsedAttachment, ParsedEmail } from "./types";

const IP_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const URL_RE = /https?:\/\/[^\s"'<>)\]]+/gi;

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

function unfoldHeaders(raw: string): { name: string; value: string }[] {
  const lines = raw.split(/\r?\n/);
  const headers: { name: string; value: string }[] = [];
  for (const line of lines) {
    if (/^[ \t]/.test(line) && headers.length) {
      headers[headers.length - 1]!.value += " " + line.trim();
    } else {
      const idx = line.indexOf(":");
      if (idx > 0) headers.push({ name: line.slice(0, idx).trim(), value: line.slice(idx + 1).trim() });
    }
  }
  return headers;
}

function get(headers: { name: string; value: string }[], name: string): string {
  const found = headers.find((h) => h.name.toLowerCase() === name.toLowerCase());
  return found ? found.value : "";
}

function all(headers: { name: string; value: string }[], name: string): string[] {
  return headers.filter((h) => h.name.toLowerCase() === name.toLowerCase()).map((h) => h.value);
}

function parseAddress(value: string): { email: string; displayName: string } {
  if (!value) return { email: "", displayName: "" };
  const angle = value.match(/<([^>]+)>/);
  const email = (angle ? angle[1]! : value).trim().replace(/^mailto:/i, "");
  let displayName = angle ? value.slice(0, value.indexOf("<")).trim() : "";
  displayName = displayName.replace(/^"|"$/g, "").trim();
  return { email, displayName };
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

function humanSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function parseAttachments(body: string): ParsedAttachment[] {
  const out: ParsedAttachment[] = [];
  const re =
    /Content-Type:\s*([^;\r\n]+)[\s\S]{0,400}?(?:filename|name)\s*=\s*"?([^";\r\n]+)"?/gi;
  let m: RegExpExecArray | null;
  const seen = new Set<string>();
  while ((m = re.exec(body))) {
    const filename = m[2]!.trim();
    if (!filename || seen.has(filename)) continue;
    if (/^(text\/plain|text\/html|multipart)/i.test(m[1]!)) continue;
    seen.add(filename);
    const after = body.slice(m.index + m[0].length, m.index + m[0].length + 400000);
    const payload = after.split(/\n\s*\n|\n--/)[0]!.replace(/[^A-Za-z0-9+/=]/g, "");
    out.push({
      filename,
      contentType: m[1]!.trim(),
      sizeLabel: humanSize(Math.max(1, Math.round((payload.length * 3) / 4))),
      // Filled in by hashAttachments() with a real SHA-256 of the decoded bytes.
      sha256: "",
      payloadBase64: payload,
    });
  }
  return out;
}

export class EmailParseError extends Error {}

export function parseEml(raw: string): ParsedEmail {
  const text = (raw ?? "").replace(/\r\n/g, "\n").trim();
  if (!text) throw new EmailParseError("The email file is empty.");

  const splitIdx = text.indexOf("\n\n");
  const headerBlock = splitIdx === -1 ? text : text.slice(0, splitIdx);
  const body = splitIdx === -1 ? "" : text.slice(splitIdx + 2);

  const headers = unfoldHeaders(headerBlock);
  const looksLikeEmail =
    headers.some((h) => ["from", "to", "subject", "message-id", "received", "date"].includes(h.name.toLowerCase()));
  if (!looksLikeEmail) {
    throw new EmailParseError("Invalid email file. Please upload a valid .EML file.");
  }

  const fromRaw = get(headers, "From");
  const { email: from, displayName } = parseAddress(fromRaw);
  const replyTo = parseAddress(get(headers, "Reply-To")).email;
  const returnPath = parseAddress(get(headers, "Return-Path")).email;
  const received = all(headers, "Received");
  const authResults = [...all(headers, "Authentication-Results"), ...all(headers, "ARC-Authentication-Results")].join(" ");

  const urls = Array.from(new Set((body.match(URL_RE) ?? []).map((u) => u.replace(/[.,;)]+$/, ""))));
  const ipsSource = [...received, headerBlock].join(" ");
  const ips = Array.from(new Set((ipsSource.match(IP_RE) ?? []).filter(isPublicIp)));

  const spfDirect = get(headers, "Received-SPF");
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
    to: parseAddress(get(headers, "To")).email || "UNKNOWN",
    replyTo: replyTo || "",
    returnPath: returnPath || "",
    subject: get(headers, "Subject") || "(no subject)",
    date: get(headers, "Date") || "UNKNOWN",
    messageId: get(headers, "Message-ID") || "UNKNOWN",
    received,
    headers,
    rawHeaders: headerBlock,
    body,
    urls,
    ips,
    attachments: parseAttachments(body),
    spfHeader: spf,
    dkimHeader: authResults ? authFromResults(authResults, "dkim") : get(headers, "DKIM-Signature") ? "SUSPICIOUS" : "UNKNOWN",
    dmarcHeader: authResults ? authFromResults(authResults, "dmarc") : "UNKNOWN",
  };
}
