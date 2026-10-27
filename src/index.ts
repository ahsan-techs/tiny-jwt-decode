/**
 * tiny-jwt-decode
 * A zero-dependency, ~500-byte JWT decoder for the browser and Node.
 *
 * This decodes a JWT's header and payload — it does NOT verify the
 * signature. A JWT's payload is base64url-encoded, not encrypted, so
 * anyone holding the token can already read it; this library just makes
 * that readable in your code. For verification, use a library that
 * checks the signature against your issuer's key.
 */

export class JwtDecodeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "JwtDecodeError";
  }
}

export interface JwtHeader {
  alg?: string;
  typ?: string;
  kid?: string;
  [key: string]: unknown;
}

export interface JwtPayload {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
  [key: string]: unknown;
}

export interface DecodedJwt<T extends JwtPayload = JwtPayload> {
  header: JwtHeader;
  payload: T;
  /** Raw signature segment, still base64url-encoded (not verified). */
  signature: string;
}

function base64UrlDecode(segment: string): string {
  const base64 = segment.replace(/-/g, "+").replace(/_/g, "/").padEnd(segment.length + ((4 - (segment.length % 4)) % 4), "=");
  const decoded = typeof atob === "function" ? atob(base64) : globalThis.Buffer!.from(base64, "base64").toString("binary");
  // Decode the binary string as UTF-8 so non-ASCII payload values come out right.
  const bytes = Uint8Array.from(decoded, (c: string) => c.charCodeAt(0));
  return typeof TextDecoder !== "undefined" ? new TextDecoder().decode(bytes) : globalThis.Buffer!.from(bytes).toString("utf-8");
}

/** Decodes a JWT's header and payload. Throws JwtDecodeError if the token is malformed. */
export function jwtDecode<T extends JwtPayload = JwtPayload>(token: string): DecodedJwt<T> {
  if (typeof token !== "string" || token.trim() === "") {
    throw new JwtDecodeError("Token must be a non-empty string.");
  }
  const parts = token.trim().split(".");
  if (parts.length !== 3) {
    throw new JwtDecodeError(`Expected a 3-part JWT (header.payload.signature), got ${parts.length} part(s).`);
  }
  const [headerPart, payloadPart, signature] = parts;
  try {
    const header = JSON.parse(base64UrlDecode(headerPart)) as JwtHeader;
    const payload = JSON.parse(base64UrlDecode(payloadPart)) as T;
    return { header, payload, signature };
  } catch (e) {
    throw new JwtDecodeError(`Could not parse token: ${e instanceof Error ? e.message : String(e)}`);
  }
}

/** True if the token's `exp` claim is in the past. Returns false if there's no `exp` claim. */
export function isJwtExpired(token: string | DecodedJwt): boolean {
  const { payload } = typeof token === "string" ? jwtDecode(token) : token;
  if (typeof payload.exp !== "number") return false;
  return Date.now() >= payload.exp * 1000;
}

export default jwtDecode;
