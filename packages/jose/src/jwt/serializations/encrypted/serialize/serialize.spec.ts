import { Buffer } from "node:buffer";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";

import { InvalidJsonWebTokenError } from "../../../../errors/invalid-jsonwebtoken.error.ts";
import { AESKWKeyManagementBackend } from "../../../../jwa/jwe/alg/aeskw/aeskw.key-management.backend.ts";
import { AESCBCContentEncryptionBackend } from "../../../../jwa/jwe/enc/aescbc/aescbc.content-encryption.backend.ts";
import type { OctetSequenceJsonWebKeyParameters } from "../../../../jwa/jwk/oct/octet-sequence.jsonwebkey.parameters.ts";
import type { JsonWebEncryptionHeaderParameters } from "../../../../jwe/header/jsonwebencryption.header.parameters.ts";
import { jwe } from "../../../../jwe/index.ts";
import { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import { claims as jwtClaims } from "../../../claims/index.ts";
import type { JsonWebTokenClaimsParameters } from "../../../claims/jsonwebtoken.claims.parameters.ts";
import { JsonWebTokenClaims } from "../../../claims/jsonwebtoken.claims.ts";
import { serialize } from "./serialize.ts";

describe("serialize()", () => {
  let now!: number;
  let claims!: JsonWebTokenClaimsParameters;

  let jwtClaimsCreateSpy: Mock;
  let jweCompactSerializeSpy: Mock;

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

  const contentEncryptionKey = Buffer.from("BNMfxVSd_P4LZJ36P6pqzmt81C1vawnbyLEA8I-cLM8", "base64url");
  const initializationVector = Buffer.from("AxY8DCtDaGlsbGljb3RoZQ", "base64url");

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

    vi.spyOn(AESKWKeyManagementBackend.prototype, "generateContentEncryptionKey").mockResolvedValueOnce(
      contentEncryptionKey,
    );

    vi.spyOn(AESCBCContentEncryptionBackend.prototype, "generateInitializationVector").mockResolvedValueOnce(
      initializationVector,
    );

    jwtClaimsCreateSpy = vi.spyOn(jwtClaims, "create");
    jweCompactSerializeSpy = vi.spyOn(jwe.compact, "serialize");
  });

  afterEach(() => {
    vi.clearAllTimers();
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("should throw when failing to serialize the Encrypted JSON Web Token.", async () => {
    const error = new InvalidJsonWebTokenError("Failed to serialize the Encrypted JSON Web Token.");

    await expect(serialize(claims, header)).rejects.toThrow(error);

    expect(jwtClaimsCreateSpy).toHaveBeenCalledExactlyOnceWith(claims);
    expect(jweCompactSerializeSpy).toHaveBeenCalledExactlyOnceWith(
      new JsonWebTokenClaims(claims).toBuffer(),
      header,
      undefined!,
    );
  });

  it("should serialize a Encrypted JSON Web Token.", async () => {
    await expect(serialize(claims, header, { jsonWebKey })).resolves.toBe(token);

    expect(jwtClaimsCreateSpy).toHaveBeenCalledExactlyOnceWith(claims);
    expect(jweCompactSerializeSpy).toHaveBeenCalledExactlyOnceWith(new JsonWebTokenClaims(claims).toBuffer(), header, {
      jsonWebKey,
    });
  });
});
