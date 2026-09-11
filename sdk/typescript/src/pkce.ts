import type { PKCEPair } from './types.js';

/**
 * Convierte un ArrayBuffer o Uint8Array a una cadena Base64URL sin padding.
 */
function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = globalThis.btoa ? globalThis.btoa(binary) : Buffer.from(bytes).toString('base64');
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Genera un par criptográfico PKCE (Code Verifier y Code Challenge S256).
 * Compatible con Node.js 18+, Bun, Deno, navegadores y Edge runtime (Web Crypto API).
 */
export async function generatePKCE(length: number = 64): Promise<PKCEPair> {
  if (length < 43 || length > 128) {
    throw new Error('La longitud del code_verifier debe estar entre 43 y 128 caracteres');
  }

  const cryptoObj = globalThis.crypto;
  if (!cryptoObj || !cryptoObj.subtle) {
    throw new Error('Web Crypto API no disponible en este entorno');
  }

  const randomBytes = new Uint8Array(length);
  cryptoObj.getRandomValues(randomBytes);
  const codeVerifier = toBase64Url(randomBytes).slice(0, length);

  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const digest = await cryptoObj.subtle.digest('SHA-256', data);
  const codeChallenge = toBase64Url(new Uint8Array(digest));

  return {
    codeVerifier,
    codeChallenge,
  };
}
