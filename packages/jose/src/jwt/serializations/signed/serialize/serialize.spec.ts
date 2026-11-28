import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";

import { InvalidJsonWebTokenError } from "../../../../errors/invalid-jsonwebtoken.error.ts";
import type { OctetSequenceJsonWebKeyParameters } from "../../../../jwa/jwk/oct/octet-sequence.jsonwebkey.parameters.ts";
import { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import type { JsonWebSignatureHeaderParameters } from "../../../../jws/header/jsonwebsignature.header.parameters.ts";
import { jws } from "../../../../jws/index.ts";
import { claims as jwtClaims } from "../../../claims/index.ts";
import type { JsonWebTokenClaimsParameters } from "../../../claims/jsonwebtoken.claims.parameters.ts";
import { JsonWebTokenClaims } from "../../../claims/jsonwebtoken.claims.ts";
import { serialize } from "./serialize.ts";

describe("serialize()", () => {
  let now!: number;
  let claims!: JsonWebTokenClaimsParameters;

  let jwtClaimsCreateSpy: Mock;
  let jwsCompactSerializeSpy: Mock;

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

    jwtClaimsCreateSpy = vi.spyOn(jwtClaims, "create");
    jwsCompactSerializeSpy = vi.spyOn(jws.compact, "serialize");
  });

  afterEach(() => {
    vi.clearAllTimers();
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("should throw when failing to serialize the Signed JSON Web Token.", async () => {
    const error = new InvalidJsonWebTokenError("Failed to serialize the Signed JSON Web Token.");

    await expect(serialize(claims, header)).rejects.toThrow(error);

    expect(jwtClaimsCreateSpy).toHaveBeenCalledExactlyOnceWith(claims);
    expect(jwsCompactSerializeSpy).toHaveBeenCalledExactlyOnceWith(
      new JsonWebTokenClaims(claims).toBuffer(),
      header,
      undefined!,
    );
  });

  it("should serialize a Signed JSON Web Token.", async () => {
    await expect(serialize(claims, header, { jsonWebKey })).resolves.toBe(token);

    expect(jwtClaimsCreateSpy).toHaveBeenCalledExactlyOnceWith(claims);
    expect(jwsCompactSerializeSpy).toHaveBeenCalledExactlyOnceWith(new JsonWebTokenClaims(claims).toBuffer(), header, {
      jsonWebKey,
    });
  });
});
