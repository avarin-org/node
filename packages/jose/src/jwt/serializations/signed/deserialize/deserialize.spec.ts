import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";

import { InvalidJsonWebTokenError } from "../../../../errors/invalid-jsonwebtoken.error.ts";
import type { OctetSequenceJsonWebKeyParameters } from "../../../../jwa/jwk/oct/octet-sequence.jsonwebkey.parameters.ts";
import { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import type { JsonWebSignatureHeaderParameters } from "../../../../jws/header/jsonwebsignature.header.parameters.ts";
import { JsonWebSignatureHeader } from "../../../../jws/header/jsonwebsignature.header.ts";
import { jws } from "../../../../jws/index.ts";
import type { JsonWebTokenClaimsParameters } from "../../../claims/jsonwebtoken.claims.parameters.ts";
import { JsonWebTokenClaims } from "../../../claims/jsonwebtoken.claims.ts";
import type { SignedJsonWebToken } from "../signed.jsonwebtoken.ts";
import { deserialize } from "./deserialize.ts";

describe("deserialize()", () => {
  let now!: number;
  let claims!: JsonWebTokenClaimsParameters;

  let jwsCompactDeserializeSpy: Mock;

  const wrongPayloadToken =
    "eyJhbGciOiJIUzI1NiJ9." +
    "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsInN1YiI6Imh0dHBz" +
    "Oi8vc3ViamVjdC5leGFtcGxlLmNvbSIsImF1ZCI6Imh0dHBzOi8vYXVkaWVuY2Uu" +
    "ZXhhbXBsZS5jb20iLCJleHAiOiIxNzg2NDk2NDAwIiwibmJmIjoxNzg2NDkyODAw" +
    "LCJpYXQiOjE3ODY0OTI4MDAsImp0aSI6Ijc1ODEwMWFjLWNlODItNDllNC05ZDQz" +
    "LTFlNWJmYzYyMjU5MyJ9." +
    "Mz4x28Ly7uNHajTYrbyaNVSSE7alUbRxpCLXfd8CvgQ";

  const token =
    "eyJhbGciOiJIUzI1NiJ9." +
    "eyJhdWQiOiJodHRwczovL2F1ZGllbmNlLmV4YW1wbGUuY29tIiwiZXhwIjoxNzg2" +
    "NDk2NDAwLCJpYXQiOjE3ODY0OTI4MDAsImlzcyI6Imh0dHBzOi8vaXNzdWVyLmV4" +
    "YW1wbGUuY29tIiwianRpIjoiNzU4MTAxYWMtY2U4Mi00OWU0LTlkNDMtMWU1YmZj" +
    "NjIyNTkzIiwibmJmIjoxNzg2NDkyODAwLCJzdWIiOiJodHRwczovL3N1YmplY3Qu" +
    "ZXhhbXBsZS5jb20ifQ." +
    "XJw3cPkuZb525-dy_7uFBZcVs8-ds6ka4hE5YhV6AhI";

  const header: JsonWebSignatureHeaderParameters = { alg: "HS256" };

  const jsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
    k: "qDM80igvja4Tg_tNsEuWDhl2bMM6_NgJEldFhIEuwqQ",
    kty: "oct",
  });

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-12T00:00:00Z"));

    now = Math.floor(Date.now() / 1000);

    claims = {
      aud: "https://audience.example.com",
      exp: now + 3600,
      iat: now,
      iss: "https://issuer.example.com",
      jti: "758101ac-ce82-49e4-9d43-1e5bfc622593",
      nbf: now,
      sub: "https://subject.example.com",
    };

    jwsCompactDeserializeSpy = vi.spyOn(jws.compact, "deserialize");
  });

  afterEach(() => {
    vi.clearAllTimers();
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("should throw when the Claims of the provided Signed JSON Web Token is invalid.", async () => {
    const error = new InvalidJsonWebTokenError("The provided JSON Web Token is invalid.");

    await expect(deserialize(wrongPayloadToken, { jsonWebKey })).rejects.toThrow(error);

    expect(jwsCompactDeserializeSpy).toHaveBeenCalledExactlyOnceWith(wrongPayloadToken, { jsonWebKey });
  });

  it("should return the deserialized Signed JSON Web Token.", async () => {
    await expect(deserialize(token, { jsonWebKey })).resolves.toStrictEqual<SignedJsonWebToken>({
      claims: new JsonWebTokenClaims(claims),
      header: new JsonWebSignatureHeader(header),
    });

    expect(jwsCompactDeserializeSpy).toHaveBeenCalledExactlyOnceWith(token, { jsonWebKey });
  });
});
