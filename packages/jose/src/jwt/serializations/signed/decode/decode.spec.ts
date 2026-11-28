import { Buffer } from "node:buffer";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { InvalidJsonWebTokenError } from "../../../../errors/invalid-jsonwebtoken.error.ts";
import type { JsonWebSignatureHeaderParameters } from "../../../../jws/header/jsonwebsignature.header.parameters.ts";
import type { JsonWebTokenClaimsParameters } from "../../../claims/jsonwebtoken.claims.parameters.ts";
import type { SignedJsonWebTokenParameters } from "../signed.jsonwebtoken.parameters.ts";
import { decode } from "./decode.ts";

const invalidTokens: any[] = [
  undefined,
  null,
  true,
  1,
  1.2,
  1n,
  Symbol("a"),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  {},
  [],
  "",
];

describe("decode()", () => {
  let claims!: JsonWebTokenClaimsParameters;

  const missingClaimsToken = "eyJhbGciOiJIUzI1NiJ9..XJw3cPkuZb525-dy_7uFBZcVs8-ds6ka4hE5YhV6AhI";

  const invalidClaimsToken = "eyJhbGciOiJIUzI1NiJ9.ew.XJw3cPkuZb525-dy_7uFBZcVs8-ds6ka4hE5YhV6AhI";

  const token =
    "eyJhbGciOiJIUzI1NiJ9." +
    "eyJhdWQiOiJodHRwczovL2F1ZGllbmNlLmV4YW1wbGUuY29tIiwiZXhwIjoxNzg2" +
    "NDk2NDAwLCJpYXQiOjE3ODY0OTI4MDAsImlzcyI6Imh0dHBzOi8vaXNzdWVyLmV4" +
    "YW1wbGUuY29tIiwianRpIjoiNzU4MTAxYWMtY2U4Mi00OWU0LTlkNDMtMWU1YmZj" +
    "NjIyNTkzIiwibmJmIjoxNzg2NDkyODAwLCJzdWIiOiJodHRwczovL3N1YmplY3Qu" +
    "ZXhhbXBsZS5jb20ifQ." +
    "XJw3cPkuZb525-dy_7uFBZcVs8-ds6ka4hE5YhV6AhI";

  const header: JsonWebSignatureHeaderParameters = { alg: "HS256" };
  const signature = Buffer.from("XJw3cPkuZb525-dy_7uFBZcVs8-ds6ka4hE5YhV6AhI", "base64url");

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-12T00:00:00Z"));

    const now = Math.floor(Date.now() / 1000);

    claims = {
      aud: "https://audience.example.com",
      exp: now + 3600,
      iat: now,
      iss: "https://issuer.example.com",
      jti: "758101ac-ce82-49e4-9d43-1e5bfc622593",
      nbf: now,
      sub: "https://subject.example.com",
    };
  });

  afterEach(() => {
    vi.clearAllTimers();
    vi.useRealTimers();
  });

  it.each(invalidTokens)("should throw when the provided Signed JSON Web Token is invalid.", (_token) => {
    const error = new InvalidJsonWebTokenError("The provided JSON Web Token is invalid.");
    expect(() => decode(_token)).toThrow(error);
  });

  it("should throw when the provided Signed JSON Web Token contains an empty JSON Web Token Claims component.", () => {
    const error = new InvalidJsonWebTokenError("The provided JSON Web Token is invalid.");
    expect(() => decode(missingClaimsToken)).toThrow(error);
  });

  it("should throw when the provided Signed JSON Web Token contains an invalid JSON Web Token Claims component.", () => {
    const error = new InvalidJsonWebTokenError("The provided JSON Web Token is invalid.");
    expect(() => decode(invalidClaimsToken)).toThrow(error);
  });

  it("should return the Signed JSON Web Token Parameters from a Signed JSON Web Signature Token.", () => {
    expect(decode(token)).toStrictEqual<SignedJsonWebTokenParameters>({
      claims,
      joseHeader: header,
      signature,
    });
  });
});
