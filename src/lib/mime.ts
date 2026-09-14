/**
 * MIME / RFC 5322 PARSING PRIMITIVES
 * ----------------------------------
 * Pure, dependency-free, browser-safe MIME decoding used by the email parser.
 *
 * Security contract:
 *  - This module only DECODES bytes. It never executes attachments, never
 *    evaluates scripts or active content, never opens URLs and never performs
 *    any network request.
 *  - All input is treated as untrusted: every decode step is wrapped so that a
 *    malformed part degrades to raw text instead of throwing.
 *
 * Modularity: the structures produced here mirror what a future FastAPI
 * backend would return, so the parser interface can be swapped without
 * touching the analysis engine.
 */

export interface MimeHeader {
  name: string;
  value: string;
}

export interface MimePart {
  headers: MimeHeader[];
  /** Lowercased mime type, e.g. "text/plain". */
  contentType: string;
  /** Parsed Content-Type parameters (charset, boundary, name, ...). */
  params: Record<string, string>;
  /** "inline" | "attachment" | "" */
  disposition: string;
  dispositionParams: Record<string, string>;
  encoding: string;
  charset: string;
  /** Decoded filename (RFC 2047 / RFC 2231 aware), if any. */
  filename: string;
  /** Decoded raw bytes for leaf parts. */
  bytes: Uint8Array;
  /** Decoded text for textual leaf parts. */
  text: string;
  /** Child parts for multipart containers. */
  children: MimePart[];
  /** True when the part could not be fully decoded (kept as raw text). */
  malformed: boolean;
}

/* ------------------------------------------------------------------ */
/* Header helpers                                                      */
/* ------------------------------------------------------------------ */

/** Unfold RFC 5322 folded headers into name/value pairs. */
export function unfoldHeaders(block: string): MimeHeader[] {
  const out: MimeHeader[] = [];
  for (const line of block.split(/\r?\n/)) {
    if (/^[ \t]/.test(line)) {
      const last = out[out.length - 1];
      if (last) last.value += " " + line.trim();
      continue;
    }
    const idx = line.indexOf(":");
    if (idx > 0) out.push({ name: line.slice(0, idx).trim(), value: line.slice(idx + 1).trim() });
  }
  return out;
}

export function headerValue(headers: MimeHeader[], name: string): string {
  const found = headers.find((h) => h.name.toLowerCase() === name.toLowerCase());
  return found ? found.value : "";
}

export function headerValues(headers: MimeHeader[], name: string): string[] {
  return headers.filter((h) => h.name.toLowerCase() === name.toLowerCase()).map((h) => h.value);
}

/* ------------------------------------------------------------------ */
/* Encoded-word (RFC 2047) decoding                                    */
/* ------------------------------------------------------------------ */

function decodeBytes(bytes: Uint8Array, charset: string): string {
  try {
    return new TextDecoder(charset || "utf-8", { fatal: false }).decode(bytes as unknown as BufferSource);
  } catch {
    try {
      return new TextDecoder("utf-8", { fatal: false }).decode(bytes as unknown as BufferSource);
    } catch {
      return Array.from(bytes)
        .map((b) => String.fromCharCode(b))
        .join("");
    }
  }
}

/** Decode any RFC 2047 encoded-words inside a header value. */
export function decodeEncodedWords(input: string): string {
  if (!input || !input.includes("=?")) return input;
  let out = input.replace(
    /=\?([^?]+)\?([BbQq])\?([^?]*)\?=(\s*)(?==\?)/g,
    (_m, cs: string, enc: string, txt: string) => decodeWord(cs, enc, txt),
  );
  out = out.replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g, (_m, cs: string, enc: string, txt: string) =>
    decodeWord(cs, enc, txt),
  );
  return out;
}

function decodeWord(charset: string, enc: string, text: string): string {
  try {
    const cs = charset.split("*")[0] ?? "utf-8";
    if (enc.toLowerCase() === "b") return decodeBytes(base64ToBytes(text), cs);
    return decodeBytes(quotedPrintableToBytes(text.replace(/_/g, " ")), cs);
  } catch {
    return text;
  }
}

/* ------------------------------------------------------------------ */
/* Transfer-encoding decoding                                          */
/* ------------------------------------------------------------------ */

export function base64ToBytes(input: string): Uint8Array {
  const clean = (input || "").replace(/[^A-Za-z0-9+/=]/g, "").replace(/=+$/, "");
  if (!clean) return new Uint8Array(0);
  const padded = clean.padEnd(Math.ceil(clean.length / 4) * 4, "=");
  try {
    const bin = atob(padded);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return new Uint8Array(0);
  }
}

export function quotedPrintableToBytes(input: string): Uint8Array {
  const text = (input || "").replace(/=\r?\n/g, "");
  const out: number[] = [];
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    if (ch === "=" && i + 2 < text.length) {
      const hex = text.slice(i + 1, i + 3);
      if (/^[0-9A-Fa-f]{2}$/.test(hex)) {
        out.push(parseInt(hex, 16));
        i += 2;
        continue;
      }
    }
    out.push(ch.charCodeAt(0) & 0xff);
  }
  return new Uint8Array(out);
}

export function bytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode(...Array.from(bytes.subarray(i, i + 0x8000)));
  }
  try {
    return btoa(bin);
  } catch {
    return "";
  }
}

function stringToBytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

/* ------------------------------------------------------------------ */
/* Content-Type / Content-Disposition parameters                       */
/* ------------------------------------------------------------------ */

function parseParams(value: string): { main: string; params: Record<string, string> } {
  const segments = splitSemicolons(value);
  const main = (segments.shift() ?? "").trim().toLowerCase();
  const raw: Record<string, string> = {};
  for (const seg of segments) {
    const eq = seg.indexOf("=");
    if (eq < 0) continue;
    const key = seg.slice(0, eq).trim().toLowerCase();
    let val = seg.slice(eq + 1).trim();
    if (val.startsWith('"')) val = val.slice(1, val.lastIndexOf('"') > 0 ? val.lastIndexOf('"') : undefined);
    raw[key] = val;
  }
  return { main, params: joinRfc2231(raw) };
}

/** Merge RFC 2231 continuations (name*0, name*1) and decode name*=charset''value. */
function joinRfc2231(raw: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  const continued: Record<string, string[]> = {};
  for (const [key, value] of Object.entries(raw)) {
    const m = key.match(/^([^*]+)\*(\d+)\*?$/);
    if (m) {
      const base = m[1]!;
      const idx = Number(m[2]);
      (continued[base] ??= [])[idx] = value;
      continue;
    }
    if (key.endsWith("*")) {
      out[key.slice(0, -1)] = decodeExtended(value);
      continue;
    }
    out[key] = value;
  }
  for (const [base, parts] of Object.entries(continued)) {
    const joined = parts.filter((p) => typeof p === "string").join("");
    out[base] = joined.includes("''") ? decodeExtended(joined) : joined;
  }
  return out;
}

function decodeExtended(value: string): string {
  const m = value.match(/^([^']*)'([^']*)'(.*)$/);
  const charset = m ? m[1] || "utf-8" : "utf-8";
  const encoded = m ? m[3]! : value;
  try {
    return decodeBytes(quotedPrintableToBytes(encoded.replace(/%/g, "=")), charset);
  } catch {
    return encoded;
  }
}

function splitSemicolons(value: string): string[] {
  const out: string[] = [];
  let cur = "";
  let quoted = false;
  for (const ch of value) {
    if (ch === '"') quoted = !quoted;
    if (ch === ";" && !quoted) {
      out.push(cur);
      cur = "";
      continue;
    }
    cur += ch;
  }
  out.push(cur);
  return out;
}

/* ------------------------------------------------------------------ */
/* Part parsing                                                        */
/* ------------------------------------------------------------------ */

export function splitHeadersAndBody(raw: string): { headerBlock: string; body: string } {
  const text = raw.replace(/\r\n/g, "\n");
  const idx = text.indexOf("\n\n");
  if (idx === -1) return { headerBlock: text, body: "" };
  return { headerBlock: text.slice(0, idx), body: text.slice(idx + 2) };
}

/** Parse one MIME entity (headers + body). Never throws. */
export function parsePart(raw: string, depth = 0): MimePart {
  const { headerBlock, body } = splitHeadersAndBody(raw);
  const headers = unfoldHeaders(headerBlock);

  const ctRaw = headerValue(headers, "Content-Type") || "text/plain";
  const { main: contentType, params } = parseParams(ctRaw);
  const cdRaw = headerValue(headers, "Content-Disposition");
  const { main: disposition, params: dispositionParams } = parseParams(cdRaw);
  const encoding = (headerValue(headers, "Content-Transfer-Encoding") || "7bit").trim().toLowerCase();
  const charset = (params["charset"] || "utf-8").replace(/["']/g, "");
  const filename = decodeEncodedWords(dispositionParams["filename"] || params["name"] || "");

  const part: MimePart = {
    headers,
    contentType,
    params,
    disposition,
    dispositionParams,
    encoding,
    charset,
    filename,
    bytes: new Uint8Array(0),
    text: "",
    children: [],
    malformed: false,
  };

  if (contentType.startsWith("multipart/") && depth < 12) {
    const boundary = params["boundary"];
    if (boundary) {
      const children = splitMultipart(body, boundary);
      if (children.length) {
        part.children = children.map((c) => parsePart(c, depth + 1));
        return part;
      }
    }
    // Malformed multipart (missing/unusable boundary): keep body as text.
    part.malformed = true;
    part.text = body;
    part.bytes = stringToBytes(body);
    return part;
  }

  try {
    if (encoding === "base64") {
      part.bytes = base64ToBytes(body);
      if (part.bytes.length === 0 && body.trim()) part.malformed = true;
    } else if (encoding === "quoted-printable") {
      part.bytes = quotedPrintableToBytes(body);
    } else {
      part.bytes = stringToBytes(body);
    }
  } catch {
    part.malformed = true;
    part.bytes = stringToBytes(body);
  }

  if (contentType.startsWith("text/") || contentType === "message/rfc822" || contentType === "") {
    part.text = decodeBytes(part.bytes, charset);
  }
  return part;
}

function splitMultipart(body: string, boundary: string): string[] {
  const delim = `--${boundary}`;
  const lines = body.split("\n");
  const parts: string[] = [];
  let current: string[] | null = null;
  for (const line of lines) {
    const trimmed = line.trimEnd();
    if (trimmed === delim || trimmed === `${delim}--`) {
      if (current) parts.push(current.join("\n"));
      current = trimmed.endsWith("--") ? null : [];
      continue;
    }
    if (current) current.push(line);
  }
  if (current && current.length) parts.push(current.join("\n"));
  return parts.filter((p) => p.trim().length > 0);
}

/** Depth-first walk over a part tree. */
export function walkParts(part: MimePart, visit: (p: MimePart) => void): void {
  visit(part);
  for (const child of part.children) walkParts(child, visit);
}

/** Strip HTML tags for text analysis. Never renders or executes anything. */
export function htmlToText(html: string): string {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/(p|div|tr|li|h[1-6])>/gi, "\n")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/[ \t]{2,}/g, " ")
    .trim();
}

export function humanSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}
