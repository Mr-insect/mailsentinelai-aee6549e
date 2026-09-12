/**
 * CRYPTOGRAPHIC HASHING
 * ---------------------
 * Real SHA-256 digests computed with the Web Crypto API
 * (crypto.subtle.digest("SHA-256", data)).
 *
 * This module is intentionally standalone and free of UI/parser imports so the
 * exact same contract can later be served by a FastAPI backend endpoint:
 * simply swap the body of `sha256Hex` for a fetch to the backend.
 *
 * Nothing here is fabricated — every value returned is a genuine SHA-256 of the
 * bytes it is given.
 */

function toBytes(data: string | ArrayBuffer | Uint8Array): Uint8Array {
  if (typeof data === "string") return new TextEncoder().encode(data);
  if (data instanceof Uint8Array) return data;
  return new Uint8Array(data);
}

function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Real SHA-256 of the supplied bytes, returned as 64 lowercase hex chars. */
export async function sha256Hex(data: string | ArrayBuffer | Uint8Array): Promise<string> {
  const bytes = toBytes(data);
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error("SHA-256 is unavailable: Web Crypto is not supported in this environment.");
  const digest = await subtle.digest("SHA-256", bytes as unknown as BufferSource);
  return toHex(digest);
}

/** Decode a base64 (MIME) payload into raw bytes so the true file digest can be taken. */
export function base64ToBytes(base64: string): Uint8Array | null {
  const clean = base64.replace(/[^A-Za-z0-9+/=]/g, "");
  if (!clean) return null;
  try {
    const binary = atob(clean.replace(/=+$/, "").padEnd(Math.ceil(clean.replace(/=+$/, "").length / 4) * 4, "="));
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

/**
 * Compute real SHA-256 digests for every parsed attachment, in place.
 * Falls back to hashing the raw base64 text when the payload cannot be decoded,
 * and leaves the value empty (surfaced as "UNAVAILABLE") if hashing fails.
 */
export async function hashAttachments(attachments: { sha256: string; payloadBase64?: string }[]): Promise<void> {
  await Promise.all(
    attachments.map(async (a) => {
      const source = a.payloadBase64 ? (base64ToBytes(a.payloadBase64) ?? a.payloadBase64) : "";
      if (!source || (typeof source !== "string" && source.length === 0)) {
        a.sha256 = "";
        return;
      }
      try {
        a.sha256 = await sha256Hex(source);
      } catch {
        a.sha256 = "";
      }
    }),
  );
}
