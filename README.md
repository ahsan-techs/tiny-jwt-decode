# tiny-jwt-decode

A zero-dependency, ~500-byte JWT decoder for the browser and Node. Decodes the header and payload, checks expiry — doesn't do signature verification, so it stays tiny.

```ts
import { jwtDecode, isJwtExpired } from "tiny-jwt-decode";

const { header, payload } = jwtDecode(token);
console.log(payload.sub, payload.exp);

if (isJwtExpired(token)) {
  // refresh or re-authenticate
}
```

## Why this exists

A JWT's payload is base64url-encoded, not encrypted — anyone holding the token can already read it. This library just makes that readable in your code, with correct UTF-8 decoding and a couple of honest TypeScript types (`JwtHeader`, `JwtPayload`), without pulling in a signature-verification dependency you may not need on the client.

**This library does not verify the signature.** If you need to trust a token's authenticity (not just read its claims), verify it server-side against your issuer's key using a library built for that.

## Install

```bash
npm install tiny-jwt-decode
```

## API

### `jwtDecode<T>(token: string): DecodedJwt<T>`

Decodes a JWT's header and payload. Throws `JwtDecodeError` if the token isn't a well-formed 3-part JWT or isn't valid JSON once decoded.

```ts
const { header, payload, signature } = jwtDecode(token);
```

### `isJwtExpired(token: string | DecodedJwt): boolean`

Returns `true` if the token's `exp` claim is in the past. Returns `false` if there's no `exp` claim at all (per the JWT spec, a missing `exp` means the token doesn't expire).

### `JwtDecodeError`

Thrown by `jwtDecode` on a malformed token. Extends `Error`.

## TypeScript

Ships its own types. Pass a type parameter for your payload shape:

```ts
interface MyClaims {
  sub: string;
  role: "admin" | "user";
}

const { payload } = jwtDecode<MyClaims>(token);
payload.role; // "admin" | "user"
```

## Size

~500 bytes gzipped, zero runtime dependencies, works in the browser (via `atob`) and in Node (via `Buffer`, as a fallback).

## Also useful

If you'd rather decode a token without installing anything, [Toolkitties' JWT Decoder](https://toolkitties.com/jwt-decoder) runs the same kind of decoding entirely in your browser, with an expiry display and no account needed.

## License

MIT
