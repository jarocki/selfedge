/**
 * crypto.ts — envelope encryption for forensic records (Stream B).
 *
 * Each record: a fresh AES-256-GCM key encrypts the plaintext; that key is
 * wrapped with the operator's RSA-OAEP-256 PUBLIC key. Only the offline PRIVATE
 * key can unwrap it. The Worker can seal but never read — confidentiality holds
 * even if the edge, KV, R2, and the deploy token are all compromised.
 *
 * Format (stable, matches the offline decrypt tool):
 *   { v:1, iv, wrappedKey, ciphertext }   — all base64
 */
export interface Sealed { v: 1; iv: string; wrappedKey: string; ciphertext: string; }

function b64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(s);
}

export async function seal(publicJwk: JsonWebKey, plaintext: string): Promise<Sealed> {
  const data = new TextEncoder().encode(plaintext);
  const rsa = await crypto.subtle.importKey(
    "jwk", publicJwk, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["wrapKey"]
  );
  const aes = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aes, data);
  const wrapped = await crypto.subtle.wrapKey("raw", aes, rsa, { name: "RSA-OAEP" });
  return { v: 1, iv: b64(iv.buffer), wrappedKey: b64(wrapped), ciphertext: b64(ciphertext) };
}
