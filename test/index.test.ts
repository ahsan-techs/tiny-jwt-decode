import { test } from "node:test";
import assert from "node:assert/strict";
import { jwtDecode, isJwtExpired, JwtDecodeError } from "../src/index";

// A sample unsigned-looking token: header {"alg":"HS256","typ":"JWT"},
// payload {"sub":"123","name":"Jane Doe","exp": 9999999999}
const SAMPLE = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJuYW1lIjoiSmFuZSBEb2UiLCJleHAiOjk5OTk5OTk5OTl9.dummy-signature";

test("decodes header and payload", () => {
  const { header, payload, signature } = jwtDecode(SAMPLE);
  assert.equal(header.alg, "HS256");
  assert.equal(payload.sub, "123");
  assert.equal((payload as { name: string }).name, "Jane Doe");
  assert.equal(signature, "dummy-signature");
});

test("throws JwtDecodeError on a malformed token", () => {
  assert.throws(() => jwtDecode("not.a.valid.jwt"), JwtDecodeError);
  assert.throws(() => jwtDecode(""), JwtDecodeError);
});

test("isJwtExpired returns false for a far-future exp", () => {
  assert.equal(isJwtExpired(SAMPLE), false);
});

test("isJwtExpired returns true for a past exp", () => {
  const expired = "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjF9.sig"; // exp: 1 (1970)
  assert.equal(isJwtExpired(expired), true);
});
