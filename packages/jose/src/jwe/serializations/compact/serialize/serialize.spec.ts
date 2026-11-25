import { Buffer } from "node:buffer";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { OctetSequenceJsonWebKeyParameters } from "../../../../jwa/index.ts";
import { AESKWKeyManagementBackend } from "../../../../jwa/jwe/alg/aeskw/aeskw.key-management.backend.ts";
import { AESCBCContentEncryptionBackend } from "../../../../jwa/jwe/enc/aescbc/aescbc.content-encryption.backend.ts";
import { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import type { JsonWebEncryptionHeaderParameters } from "../../../header/jsonwebencryption.header.parameters.ts";
import { serialize } from "./serialize.ts";

const invalidPlaintexts: any[] = [
  undefined,
  null,
  true,
  1,
  1.2,
  1n,
  "a",
  Symbol("a"),
  Buffer,
  () => 1,
  {},
  [],
  Buffer.alloc(0),
];

const invalidProtectedHeaders: any[] = [
  undefined,
  null,
  true,
  1,
  1.2,
  1n,
  "a",
  Symbol("a"),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  [],
];

const invalidSerializeOptions: any[] = [null, true, 1, 1.2, 1n, "a", Symbol("a"), Buffer, Buffer.alloc(1), () => 1, []];

const invalidJsonWebKeys: any[] = [
  undefined,
  null,
  true,
  1,
  1.2,
  1n,
  "a",
  Symbol("a"),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  {},
  [],
];

const invalidDetacheds: any[] = [
  undefined,
  null,
  1,
  1.2,
  1n,
  "a",
  Symbol("a"),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  {},
  [],
];

describe("serialize()", () => {
  const attachedTokenWithJsonWebKeyInProtectedHeader =
    "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiandrIjp7Imsi" +
    "OiJHYXdnZ3VGeUdyV0thdjdBWDRWS1VnIiwia3R5Ijoib2N0In19." +
    "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ." +
    "AxY8DCtDaGlsbGljb3RoZQ." +
    "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY." +
    "fypTwItpcf-hUYRVp9fyjA";

  const attachedToken =
    "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." +
    "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ." +
    "AxY8DCtDaGlsbGljb3RoZQ." +
    "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY." +
    "U0m_YmjN04DJvceFICbCVQ";

  const detachedToken =
    "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." +
    "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ." +
    "AxY8DCtDaGlsbGljb3RoZQ." +
    "." +
    "U0m_YmjN04DJvceFICbCVQ";

  const compressedAttachedToken =
    "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIn0." +
    "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ." +
    "AxY8DCtDaGlsbGljb3RoZQ." +
    "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA." +
    "PGfg9jnB_-hnQBGbNu8jBQ";

  const compressedDetachedToken =
    "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIn0." +
    "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ." +
    "AxY8DCtDaGlsbGljb3RoZQ." +
    "." +
    "PGfg9jnB_-hnQBGbNu8jBQ";

  const plaintext = Buffer.from("Live long and prosper.");
  const protectedHeader: JsonWebEncryptionHeaderParameters = { alg: "A128KW", enc: "A128CBC-HS256" };
  const protectedCompressedHeader: JsonWebEncryptionHeaderParameters = {
    alg: "A128KW",
    enc: "A128CBC-HS256",
    zip: "DEF",
  };

  const contentEncryptionKey = Buffer.from("BNMfxVSd_P4LZJ36P6pqzmt81C1vawnbyLEA8I-cLM8", "base64url");
  const initializationVector = Buffer.from("AxY8DCtDaGlsbGljb3RoZQ", "base64url");

  const jsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({ k: "GawgguFyGrWKav7AX4VKUg", kty: "oct" });

  beforeEach(() => {
    vi.spyOn(AESKWKeyManagementBackend.prototype, "generateContentEncryptionKey").mockResolvedValueOnce(
      contentEncryptionKey,
    );

    vi.spyOn(AESCBCContentEncryptionBackend.prototype, "generateInitializationVector").mockResolvedValueOnce(
      initializationVector,
    );
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it.each(invalidPlaintexts)("should throw when the provided Plaintext is invalid.", async (_plaintext) => {
    const error = new TypeError("The provided Plaintext is invalid.");
    await expect(serialize(_plaintext, protectedHeader)).rejects.toThrow(error);
  });

  it.each(invalidProtectedHeaders)(
    "should throw when the provided JSON Web Encryption Protected Header is invalid.",
    async (_protectedHeader) => {
      const error = new TypeError("The provided JSON Web Encryption Protected Header is invalid.");
      await expect(serialize(plaintext, _protectedHeader)).rejects.toThrow(error);
    },
  );

  it.each(invalidSerializeOptions)(
    "should throw when the provided Compact JSON Web Encryption Serialize Options is invalid.",
    async (options) => {
      const error = new TypeError("The provided Compact JSON Web Encryption Serialize Options is invalid.");
      await expect(serialize(plaintext, protectedHeader, options)).rejects.toThrow(error);
    },
  );

  it.each(invalidJsonWebKeys)(
    'should throw when the provided Compact JSON Web Encryption Serialize Option "jsonWebKey" is invalid.',
    async (_jsonWebKey) => {
      const error = new TypeError('The provided Compact JSON Web Encryption Serialize Option "jsonWebKey" is invalid.');
      await expect(serialize(plaintext, protectedHeader, { jsonWebKey: _jsonWebKey })).rejects.toThrow(error);
    },
  );

  it.each(invalidDetacheds)(
    'should throw when the provided Compact JSON Web Encryption Serialize Option "detached" is invalid.',
    async (detached) => {
      const error = new TypeError('The provided Compact JSON Web Encryption Serialize Option "detached" is invalid.');
      await expect(serialize(plaintext, protectedHeader, { detached })).rejects.toThrow(error);
    },
  );

  it("should serialize a Compact JSON Web Encryption Attached Token with the JSON Web Key in the Protected Header.", async () => {
    await expect(serialize(plaintext, { ...protectedHeader, jwk: jsonWebKey.parameters })).resolves.toStrictEqual(
      attachedTokenWithJsonWebKeyInProtectedHeader,
    );
  });

  it("should serialize a Compact JSON Web Encryption Attached Token.", async () => {
    await expect(serialize(plaintext, protectedHeader, { jsonWebKey })).resolves.toStrictEqual(attachedToken);
  });

  it("should serialize a Compact JSON Web Encryption Detached Token.", async () => {
    await expect(serialize(plaintext, protectedHeader, { detached: true, jsonWebKey })).resolves.toStrictEqual(
      detachedToken,
    );
  });

  it("should serialize a Compact JSON Web Encryption Compressed Attached Token.", async () => {
    await expect(serialize(plaintext, protectedCompressedHeader, { jsonWebKey })).resolves.toStrictEqual(
      compressedAttachedToken,
    );
  });

  it("should serialize a Compact JSON Web Encryption Compressed Detached Token.", async () => {
    await expect(
      serialize(plaintext, protectedCompressedHeader, { detached: true, jsonWebKey }),
    ).resolves.toStrictEqual(compressedDetachedToken);
  });
});
