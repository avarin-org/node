import { Buffer } from "node:buffer";
import * as crypto from "node:crypto";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";

import { InvalidJoseHeaderError } from "../../../../errors/invalid-jose-header.error.ts";
import { InvalidJsonWebEncryptionError } from "../../../../errors/invalid-jsonwebencryption.error.ts";
import { InvalidJsonWebKeyError } from "../../../../errors/invalid-jsonwebkey.error.ts";
import { JsonWebEncryptionHeader } from "../../../../jwe/header/jsonwebencryption.header.ts";
import { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import type { OctetSequenceJsonWebKeyParameters } from "../../../jwk/oct/octet-sequence.jsonwebkey.parameters.ts";
import type { RsaJsonWebKeyParameters } from "../../../jwk/rsa/rsa.jsonwebkey.parameters.ts";
import { AESKWKeyManagementBackend } from "../aeskw/aeskw.key-management.backend.ts";
import type { KeyManagementAlgorithm } from "../key-management-algorithm.type.ts";
import type { PBES2JsonWebEncryptionHeaderParameters } from "./pbes2.jsonwebencryption.header.parameters.ts";
import { PBES2KeyManagementBackend } from "./pbes2.key-management.backend.ts";

vi.mock(import("node:crypto"), async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, randomBytes: vi.fn() };
});

const contentEncryptionKey = Buffer.from("bxsZNEIdFE5csDjwQdBScKGDJDfK7LmsgReZwsMw_bY", "base64url");

const invalidP2Ss: any[] = [
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
  "1234567",
];

const invalidP2Cs: any[] = [
  undefined,
  null,
  true,
  1n,
  "a",
  Symbol("a"),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  {},
  [],
  1.2,
  999,
];

describe("PBES2 Key Management Backend", () => {
  const jsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
    k: Buffer.from("Thus from my lips, by yours, my sin is purged.", "utf8").toString("base64url"),
    kty: "oct",
  });

  const wrongAlgJsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
    alg: "HS256",
    k: "qDM80igvja4Tg_tNsEuWDhl2bMM6_NgJEldFhIEuwqQ",
    kty: "oct",
  });

  const wrongKtyJsonWebKey = new JsonWebKey<RsaJsonWebKeyParameters>({
    e: "AQAB",
    kty: "RSA",
    n:
      "xjpFydzTbByzL5jhEa2yQO63dpS9d9SKaN107AR69skKiTR4uK1c4SzDt4YcurDB" +
      "yhgKNzeBo6Vq3IRrkrltp97LKWfeZdM-leGt8-UTZEWqrNf3UGOEj8kI6lbjiG-S" +
      "n_yNHcVA9qBV22norZkgXctHLeFbY6TmpD-I8_UiplZUHoc9KlYc7crCQRa-O7tK" +
      "FDULNTMjjifc0dmuYP7ZcYAZXmRmoOpQuDr8s7OZY7TAqN0btMfA7RpUCWLT6TMR" +
      "QPX8GcyTxfbkOrSTFueKMHVNdXDtl068XXJ9mkjORiEmwlzqSBoxdeLWcNf_u20S" +
      "5JG5iK0nsm1uZYu-02XN-w",
  });

  const wrongEncryptedKey = Buffer.from("ZYr4n0Jg_9jOaXA4TZ0SXYjz7DDk-x7NG_PSW31YwzkRll1FzRbT-g", "base64url");

  beforeEach(() => {
    vi.mocked(crypto.randomBytes).mockImplementation((_, cb) => cb(null, contentEncryptionKey));
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  describe("PBES2-HS256+A128KW", () => {
    const backend = new PBES2KeyManagementBackend("PBES2-HS256+A128KW");

    let aeskwWrapSpy: Mock<AESKWKeyManagementBackend["wrap"]>;
    let aeskwUnwrapSpy: Mock<AESKWKeyManagementBackend["unwrap"]>;

    const encryptedKey = Buffer.from("TrqXOwuNUfDV9VPTNbyGvEJ9JMjefAVn-TR1uIxR9p6hsRQh9Tk7BA", "base64url");

    let header: JsonWebEncryptionHeader<PBES2JsonWebEncryptionHeaderParameters>;

    const wrongJsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
      k: Buffer.from("Bad password.", "utf8").toString("base64url"),
      kty: "oct",
    });

    const wrongP2SHeader = new JsonWebEncryptionHeader<PBES2JsonWebEncryptionHeaderParameters>({
      alg: "PBES2-HS256+A128KW",
      enc: "A128CBC-HS256",
      p2c: 4096,
      p2s: "QpGYnmJUuIdGFzIzaiEvJw",
    });

    const wrongP2CHeader = new JsonWebEncryptionHeader<PBES2JsonWebEncryptionHeaderParameters>({
      alg: "PBES2-HS256+A128KW",
      enc: "A128CBC-HS256",
      p2c: 8192,
      p2s: "2WCTcJZ1Rvd_CJuJripQ1w",
    });

    beforeEach(() => {
      aeskwWrapSpy = vi.spyOn(backend["aesKeyWrapBackend"], "wrap");
      aeskwUnwrapSpy = vi.spyOn(backend["aesKeyWrapBackend"], "unwrap");

      header = new JsonWebEncryptionHeader<PBES2JsonWebEncryptionHeaderParameters>({
        alg: "PBES2-HS256+A128KW",
        enc: "A128CBC-HS256",
        p2c: 4096,
        p2s: "2WCTcJZ1Rvd_CJuJripQ1w",
      });
    });

    describe("constructor", () => {
      it("should have a 128-bit AES Key Wrap JSON Web Encryption Key Management Backend.", () => {
        expect(backend["aesKeyWrapBackend"]).toBeInstanceOf(AESKWKeyManagementBackend);
        expect(backend["aesKeyWrapBackend"].name).toBe<KeyManagementAlgorithm>("A128KW");
      });
    });

    describe("wrap()", () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the Key Management Algorithm.', async () => {
        const error = new InvalidJsonWebKeyError(
          "The provided JSON Web Key cannot be used by the Key Management Algorithm.",
        );

        await expect(backend.wrap(contentEncryptionKey, wrongAlgJsonWebKey, header)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        const error = new InvalidJsonWebKeyError('The Key Management Algorithm only accepts "oct" JSON Web Keys.');
        await expect(backend.wrap(contentEncryptionKey, wrongKtyJsonWebKey as any, header)).rejects.toThrow(error);
      });

      it.each(invalidP2Ss)('should throw when the provided JOSE Header Parameter "p2s" is invalid.', async (p2s) => {
        Reflect.set(header.parameters, "p2s", p2s);
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "p2s".');
        await expect(backend.wrap(contentEncryptionKey, jsonWebKey, header)).rejects.toThrow(error);
      });

      it.each(invalidP2Cs)('should throw when the provided JOSE Header Parameter "p2c" is invalid.', async (p2c) => {
        Reflect.set(header.parameters, "p2c", p2c);
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "p2c".');
        await expect(backend.wrap(contentEncryptionKey, jsonWebKey, header)).rejects.toThrow(error);
      });

      it("should wrap the provided Content Encryption Key.", async () => {
        await expect(backend.wrap(contentEncryptionKey, jsonWebKey, header)).resolves.toStrictEqual(encryptedKey);
        expect(aeskwWrapSpy).toHaveBeenCalledExactlyOnceWith(contentEncryptionKey, expect.any(JsonWebKey), header);
      });
    });

    describe("unwrap()", () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the Key Management Algorithm.', async () => {
        const error = new InvalidJsonWebKeyError(
          "The provided JSON Web Key cannot be used by the Key Management Algorithm.",
        );

        await expect(backend.unwrap(encryptedKey, wrongAlgJsonWebKey, header)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        const error = new InvalidJsonWebKeyError('The Key Management Algorithm only accepts "oct" JSON Web Keys.');
        await expect(backend.unwrap(encryptedKey, wrongKtyJsonWebKey as any, header)).rejects.toThrow(error);
      });

      it.each(invalidP2Ss)('should throw when the provided JOSE Header Parameter "p2s" is invalid.', async (p2s) => {
        Reflect.set(header.parameters, "p2s", p2s);
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "p2s".');
        await expect(backend.unwrap(encryptedKey, jsonWebKey, header)).rejects.toThrow(error);
      });

      it.each(invalidP2Cs)('should throw when the provided JOSE Header Parameter "p2c" is invalid.', async (p2c) => {
        Reflect.set(header.parameters, "p2c", p2c);
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "p2c".');
        await expect(backend.unwrap(encryptedKey, jsonWebKey, header)).rejects.toThrow(error);
      });

      it("should throw when the provided Encrypted Key is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
        await expect(backend.unwrap(wrongEncryptedKey, jsonWebKey, header)).rejects.toThrow(error);
      });

      it("should throw when the provided JSON Web Key is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
        await expect(backend.unwrap(encryptedKey, wrongJsonWebKey, header)).rejects.toThrow(error);
      });

      it('should throw when providing the wrong JSON Web Encryption Header Parameter "iv".', async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
        await expect(backend.unwrap(encryptedKey, jsonWebKey, wrongP2SHeader)).rejects.toThrow(error);
      });

      it('should throw when providing the wrong JSON Web Encryption Header Parameter "tag".', async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
        await expect(backend.unwrap(encryptedKey, jsonWebKey, wrongP2CHeader)).rejects.toThrow(error);
      });

      it("should unwrap the provided Encrypted Key.", async () => {
        await expect(backend.unwrap(encryptedKey, jsonWebKey, header)).resolves.toStrictEqual(contentEncryptionKey);
        expect(aeskwUnwrapSpy).toHaveBeenCalledExactlyOnceWith(encryptedKey, expect.any(JsonWebKey), header);
      });
    });

    describe("generateContentEncryptionKey()", () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the Key Management Algorithm.', async () => {
        const error = new InvalidJsonWebKeyError(
          "The provided JSON Web Key cannot be used by the Key Management Algorithm.",
        );

        await expect(backend.generateContentEncryptionKey(wrongAlgJsonWebKey, header)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        const error = new InvalidJsonWebKeyError('The Key Management Algorithm only accepts "oct" JSON Web Keys.');
        await expect(backend.generateContentEncryptionKey(wrongKtyJsonWebKey as any, header)).rejects.toThrow(error);
      });

      it("should generate a Content Encryption Key.", async () => {
        await expect(backend.generateContentEncryptionKey(jsonWebKey, header)).resolves.toStrictEqual(
          contentEncryptionKey,
        );
      });
    });
  });

  describe("PBES2-HS384+A192KW", () => {
    const backend = new PBES2KeyManagementBackend("PBES2-HS384+A192KW");

    let aeskwWrapSpy: Mock<AESKWKeyManagementBackend["wrap"]>;
    let aeskwUnwrapSpy: Mock<AESKWKeyManagementBackend["unwrap"]>;

    const encryptedKey = Buffer.from("QaWVsah2J1z6QQCWWF98wGuf-NB8lmsJyeLY7WxW5MtiCePRBTNbMA", "base64url");

    let header: JsonWebEncryptionHeader<PBES2JsonWebEncryptionHeaderParameters>;

    const wrongJsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
      k: Buffer.from("Bad password.", "utf8").toString("base64url"),
      kty: "oct",
    });

    const wrongP2SHeader = new JsonWebEncryptionHeader<PBES2JsonWebEncryptionHeaderParameters>({
      alg: "PBES2-HS384+A192KW",
      enc: "A128CBC-HS256",
      p2c: 4096,
      p2s: "QpGYnmJUuIdGFzIzaiEvJw",
    });

    const wrongP2CHeader = new JsonWebEncryptionHeader<PBES2JsonWebEncryptionHeaderParameters>({
      alg: "PBES2-HS384+A192KW",
      enc: "A128CBC-HS256",
      p2c: 8192,
      p2s: "2WCTcJZ1Rvd_CJuJripQ1w",
    });

    beforeEach(() => {
      aeskwWrapSpy = vi.spyOn(backend["aesKeyWrapBackend"], "wrap");
      aeskwUnwrapSpy = vi.spyOn(backend["aesKeyWrapBackend"], "unwrap");

      header = new JsonWebEncryptionHeader<PBES2JsonWebEncryptionHeaderParameters>({
        alg: "PBES2-HS384+A192KW",
        enc: "A128CBC-HS256",
        p2c: 4096,
        p2s: "2WCTcJZ1Rvd_CJuJripQ1w",
      });
    });

    describe("constructor", () => {
      it("should have a 192-bit AES Key Wrap JSON Web Encryption Key Management Backend.", () => {
        expect(backend["aesKeyWrapBackend"]).toBeInstanceOf(AESKWKeyManagementBackend);
        expect(backend["aesKeyWrapBackend"].name).toBe<KeyManagementAlgorithm>("A192KW");
      });
    });

    describe("wrap()", () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the Key Management Algorithm.', async () => {
        const error = new InvalidJsonWebKeyError(
          "The provided JSON Web Key cannot be used by the Key Management Algorithm.",
        );

        await expect(backend.wrap(contentEncryptionKey, wrongAlgJsonWebKey, header)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        const error = new InvalidJsonWebKeyError('The Key Management Algorithm only accepts "oct" JSON Web Keys.');
        await expect(backend.wrap(contentEncryptionKey, wrongKtyJsonWebKey as any, header)).rejects.toThrow(error);
      });

      it.each(invalidP2Ss)('should throw when the provided JOSE Header Parameter "p2s" is invalid.', async (p2s) => {
        Reflect.set(header.parameters, "p2s", p2s);
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "p2s".');
        await expect(backend.wrap(contentEncryptionKey, jsonWebKey, header)).rejects.toThrow(error);
      });

      it.each(invalidP2Cs)('should throw when the provided JOSE Header Parameter "p2c" is invalid.', async (p2c) => {
        Reflect.set(header.parameters, "p2c", p2c);
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "p2c".');
        await expect(backend.wrap(contentEncryptionKey, jsonWebKey, header)).rejects.toThrow(error);
      });

      it("should wrap the provided Content Encryption Key.", async () => {
        await expect(backend.wrap(contentEncryptionKey, jsonWebKey, header)).resolves.toStrictEqual(encryptedKey);
        expect(aeskwWrapSpy).toHaveBeenCalledExactlyOnceWith(contentEncryptionKey, expect.any(JsonWebKey), header);
      });
    });

    describe("unwrap()", () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the Key Management Algorithm.', async () => {
        const error = new InvalidJsonWebKeyError(
          "The provided JSON Web Key cannot be used by the Key Management Algorithm.",
        );

        await expect(backend.unwrap(encryptedKey, wrongAlgJsonWebKey, header)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        const error = new InvalidJsonWebKeyError('The Key Management Algorithm only accepts "oct" JSON Web Keys.');
        await expect(backend.unwrap(encryptedKey, wrongKtyJsonWebKey as any, header)).rejects.toThrow(error);
      });

      it.each(invalidP2Ss)('should throw when the provided JOSE Header Parameter "p2s" is invalid.', async (p2s) => {
        Reflect.set(header.parameters, "p2s", p2s);
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "p2s".');
        await expect(backend.unwrap(encryptedKey, jsonWebKey, header)).rejects.toThrow(error);
      });

      it.each(invalidP2Cs)('should throw when the provided JOSE Header Parameter "p2c" is invalid.', async (p2c) => {
        Reflect.set(header.parameters, "p2c", p2c);
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "p2c".');
        await expect(backend.unwrap(encryptedKey, jsonWebKey, header)).rejects.toThrow(error);
      });

      it("should throw when the provided Encrypted Key is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
        await expect(backend.unwrap(wrongEncryptedKey, jsonWebKey, header)).rejects.toThrow(error);
      });

      it("should throw when the provided JSON Web Key is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
        await expect(backend.unwrap(encryptedKey, wrongJsonWebKey, header)).rejects.toThrow(error);
      });

      it('should throw when providing the wrong JSON Web Encryption Header Parameter "iv".', async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
        await expect(backend.unwrap(encryptedKey, jsonWebKey, wrongP2SHeader)).rejects.toThrow(error);
      });

      it('should throw when providing the wrong JSON Web Encryption Header Parameter "tag".', async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
        await expect(backend.unwrap(encryptedKey, jsonWebKey, wrongP2CHeader)).rejects.toThrow(error);
      });

      it("should unwrap the provided Encrypted Key.", async () => {
        await expect(backend.unwrap(encryptedKey, jsonWebKey, header)).resolves.toStrictEqual(contentEncryptionKey);
        expect(aeskwUnwrapSpy).toHaveBeenCalledExactlyOnceWith(encryptedKey, expect.any(JsonWebKey), header);
      });
    });

    describe("generateContentEncryptionKey()", () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the Key Management Algorithm.', async () => {
        const error = new InvalidJsonWebKeyError(
          "The provided JSON Web Key cannot be used by the Key Management Algorithm.",
        );

        await expect(backend.generateContentEncryptionKey(wrongAlgJsonWebKey, header)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        const error = new InvalidJsonWebKeyError('The Key Management Algorithm only accepts "oct" JSON Web Keys.');
        await expect(backend.generateContentEncryptionKey(wrongKtyJsonWebKey as any, header)).rejects.toThrow(error);
      });

      it("should generate a Content Encryption Key.", async () => {
        await expect(backend.generateContentEncryptionKey(jsonWebKey, header)).resolves.toStrictEqual(
          contentEncryptionKey,
        );
      });
    });
  });

  describe("PBES2-HS512+A256KW", () => {
    const backend = new PBES2KeyManagementBackend("PBES2-HS512+A256KW");

    let aeskwWrapSpy: Mock<AESKWKeyManagementBackend["wrap"]>;
    let aeskwUnwrapSpy: Mock<AESKWKeyManagementBackend["unwrap"]>;

    const encryptedKey = Buffer.from("T0eFFwZwsNPWK0y1j6TUd-EbvYGAq6uLtFKuhO3_eGsstZ4Uq3L8XQ", "base64url");

    let header: JsonWebEncryptionHeader<PBES2JsonWebEncryptionHeaderParameters>;

    const wrongJsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
      k: Buffer.from("Bad password.", "utf8").toString("base64url"),
      kty: "oct",
    });

    const wrongP2SHeader = new JsonWebEncryptionHeader<PBES2JsonWebEncryptionHeaderParameters>({
      alg: "PBES2-HS512+A256KW",
      enc: "A128CBC-HS256",
      p2c: 4096,
      p2s: "QpGYnmJUuIdGFzIzaiEvJw",
    });

    const wrongP2CHeader = new JsonWebEncryptionHeader<PBES2JsonWebEncryptionHeaderParameters>({
      alg: "PBES2-HS512+A256KW",
      enc: "A128CBC-HS256",
      p2c: 8192,
      p2s: "2WCTcJZ1Rvd_CJuJripQ1w",
    });

    beforeEach(() => {
      aeskwWrapSpy = vi.spyOn(backend["aesKeyWrapBackend"], "wrap");
      aeskwUnwrapSpy = vi.spyOn(backend["aesKeyWrapBackend"], "unwrap");

      header = new JsonWebEncryptionHeader<PBES2JsonWebEncryptionHeaderParameters>({
        alg: "PBES2-HS512+A256KW",
        enc: "A128CBC-HS256",
        p2c: 4096,
        p2s: "2WCTcJZ1Rvd_CJuJripQ1w",
      });
    });

    describe("constructor", () => {
      it("should have a 256-bit AES Key Wrap JSON Web Encryption Key Management Backend.", () => {
        expect(backend["aesKeyWrapBackend"]).toBeInstanceOf(AESKWKeyManagementBackend);
        expect(backend["aesKeyWrapBackend"].name).toBe<KeyManagementAlgorithm>("A256KW");
      });
    });

    describe("wrap()", () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the Key Management Algorithm.', async () => {
        const error = new InvalidJsonWebKeyError(
          "The provided JSON Web Key cannot be used by the Key Management Algorithm.",
        );

        await expect(backend.wrap(contentEncryptionKey, wrongAlgJsonWebKey, header)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        const error = new InvalidJsonWebKeyError('The Key Management Algorithm only accepts "oct" JSON Web Keys.');
        await expect(backend.wrap(contentEncryptionKey, wrongKtyJsonWebKey as any, header)).rejects.toThrow(error);
      });

      it.each(invalidP2Ss)('should throw when the provided JOSE Header Parameter "p2s" is invalid.', async (p2s) => {
        Reflect.set(header.parameters, "p2s", p2s);
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "p2s".');
        await expect(backend.wrap(contentEncryptionKey, jsonWebKey, header)).rejects.toThrow(error);
      });

      it.each(invalidP2Cs)('should throw when the provided JOSE Header Parameter "p2c" is invalid.', async (p2c) => {
        Reflect.set(header.parameters, "p2c", p2c);
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "p2c".');
        await expect(backend.wrap(contentEncryptionKey, jsonWebKey, header)).rejects.toThrow(error);
      });

      it("should wrap the provided Content Encryption Key.", async () => {
        await expect(backend.wrap(contentEncryptionKey, jsonWebKey, header)).resolves.toStrictEqual(encryptedKey);
        expect(aeskwWrapSpy).toHaveBeenCalledExactlyOnceWith(contentEncryptionKey, expect.any(JsonWebKey), header);
      });
    });

    describe("unwrap()", () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the Key Management Algorithm.', async () => {
        const error = new InvalidJsonWebKeyError(
          "The provided JSON Web Key cannot be used by the Key Management Algorithm.",
        );

        await expect(backend.unwrap(encryptedKey, wrongAlgJsonWebKey, header)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        const error = new InvalidJsonWebKeyError('The Key Management Algorithm only accepts "oct" JSON Web Keys.');
        await expect(backend.unwrap(encryptedKey, wrongKtyJsonWebKey as any, header)).rejects.toThrow(error);
      });

      it.each(invalidP2Ss)('should throw when the provided JOSE Header Parameter "p2s" is invalid.', async (p2s) => {
        Reflect.set(header.parameters, "p2s", p2s);
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "p2s".');
        await expect(backend.unwrap(encryptedKey, jsonWebKey, header)).rejects.toThrow(error);
      });

      it.each(invalidP2Cs)('should throw when the provided JOSE Header Parameter "p2c" is invalid.', async (p2c) => {
        Reflect.set(header.parameters, "p2c", p2c);
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "p2c".');
        await expect(backend.unwrap(encryptedKey, jsonWebKey, header)).rejects.toThrow(error);
      });

      it("should throw when the provided Encrypted Key is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
        await expect(backend.unwrap(wrongEncryptedKey, jsonWebKey, header)).rejects.toThrow(error);
      });

      it("should throw when the provided JSON Web Key is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
        await expect(backend.unwrap(encryptedKey, wrongJsonWebKey, header)).rejects.toThrow(error);
      });

      it('should throw when providing the wrong JSON Web Encryption Header Parameter "iv".', async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
        await expect(backend.unwrap(encryptedKey, jsonWebKey, wrongP2SHeader)).rejects.toThrow(error);
      });

      it('should throw when providing the wrong JSON Web Encryption Header Parameter "tag".', async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
        await expect(backend.unwrap(encryptedKey, jsonWebKey, wrongP2CHeader)).rejects.toThrow(error);
      });

      it("should unwrap the provided Encrypted Key.", async () => {
        await expect(backend.unwrap(encryptedKey, jsonWebKey, header)).resolves.toStrictEqual(contentEncryptionKey);
        expect(aeskwUnwrapSpy).toHaveBeenCalledExactlyOnceWith(encryptedKey, expect.any(JsonWebKey), header);
      });
    });

    describe("generateContentEncryptionKey()", () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the Key Management Algorithm.', async () => {
        const error = new InvalidJsonWebKeyError(
          "The provided JSON Web Key cannot be used by the Key Management Algorithm.",
        );

        await expect(backend.generateContentEncryptionKey(wrongAlgJsonWebKey, header)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        const error = new InvalidJsonWebKeyError('The Key Management Algorithm only accepts "oct" JSON Web Keys.');
        await expect(backend.generateContentEncryptionKey(wrongKtyJsonWebKey as any, header)).rejects.toThrow(error);
      });

      it("should generate a Content Encryption Key.", async () => {
        await expect(backend.generateContentEncryptionKey(jsonWebKey, header)).resolves.toStrictEqual(
          contentEncryptionKey,
        );
      });
    });
  });
});
