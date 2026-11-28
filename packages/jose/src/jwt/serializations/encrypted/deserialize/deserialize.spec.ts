import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";

import { InvalidJsonWebTokenError } from "../../../../errors/invalid-jsonwebtoken.error.ts";
import type { OctetSequenceJsonWebKeyParameters } from "../../../../jwa/jwk/oct/octet-sequence.jsonwebkey.parameters.ts";
import type { JsonWebEncryptionHeaderParameters } from "../../../../jwe/header/jsonwebencryption.header.parameters.ts";
import { JsonWebEncryptionHeader } from "../../../../jwe/header/jsonwebencryption.header.ts";
import { jwe } from "../../../../jwe/index.ts";
import { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import type { JsonWebTokenClaimsParameters } from "../../../claims/jsonwebtoken.claims.parameters.ts";
import { JsonWebTokenClaims } from "../../../claims/jsonwebtoken.claims.ts";
import type { EncryptedJsonWebToken } from "../encrypted.jsonwebtoken.ts";
import { deserialize } from "./deserialize.ts";

describe("deserialize()", () => {
  let now!: number;
  let claims!: JsonWebTokenClaimsParameters;

  let jweCompactDeserializeSpy: Mock;

  const missingCiphertextToken =
    "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." +
    "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ." +
    "AxY8DCtDaGlsbGljb3RoZQ." +
    "." +
    "QUEdwSQHNnHdx5iOT6crEA";

  const token =
    "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." +
    "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ." +
    "AxY8DCtDaGlsbGljb3RoZQ." +
    "PILdp08fMzHVXOwvLewymK1pKxWHPqFBABvtDKt9mitJoQo8MF3psrU0cbTlB7Zf" +
    "7L65jyZ0dnovLDunUvU2Pjp6o8FDo4b36ud52tOGBji6Q6GMdin59cKc6P3cR74j" +
    "eZAcJvp-INXHDgde2KYthMp5JqRHxX_tfh1wmUXYDoMUhYWjSZRIanKb3YD2pSM3" +
    "CcPOZmxHq95e-flDYHdpwS32v6opRhDO716WuVv9jOmnfJeoyfPC5WRWmJAB8UQB" +
    "cgN2QZC6kElBBJR3BX03BQ." +
    "QUEdwSQHNnHdx5iOT6crEA";

  const header: JsonWebEncryptionHeaderParameters = { alg: "A128KW", enc: "A128CBC-HS256" };

  const jsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({ k: "GawgguFyGrWKav7AX4VKUg", kty: "oct" });

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

    jweCompactDeserializeSpy = vi.spyOn(jwe.compact, "deserialize");
  });

  afterEach(() => {
    vi.clearAllTimers();
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("should throw when the Claims of the provided Encrypted JSON Web Token is invalid.", async () => {
    const error = new InvalidJsonWebTokenError("The provided JSON Web Token is invalid.");

    await expect(deserialize(missingCiphertextToken, { jsonWebKey })).rejects.toThrow(error);

    expect(jweCompactDeserializeSpy).toHaveBeenCalledExactlyOnceWith(missingCiphertextToken, { jsonWebKey });
  });

  it("should return the deserialized Encrypted JSON Web Token.", async () => {
    await expect(deserialize(token, { jsonWebKey })).resolves.toStrictEqual<EncryptedJsonWebToken>({
      claims: new JsonWebTokenClaims(claims),
      header: new JsonWebEncryptionHeader(header),
    });

    expect(jweCompactDeserializeSpy).toHaveBeenCalledExactlyOnceWith(token, { jsonWebKey });
  });
});
