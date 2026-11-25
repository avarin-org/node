import { Buffer } from "node:buffer";
import * as crypto from "node:crypto";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { InvalidJoseHeaderError } from "../../../../errors/invalid-jose-header.error.ts";
import { InvalidJsonWebEncryptionError } from "../../../../errors/invalid-jsonwebencryption.error.ts";
import { InvalidJsonWebKeyError } from "../../../../errors/invalid-jsonwebkey.error.ts";
import { JsonWebEncryptionHeader } from "../../../../jwe/header/jsonwebencryption.header.ts";
import { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import type { OctetSequenceJsonWebKeyParameters } from "../../../jwk/oct/octet-sequence.jsonwebkey.parameters.ts";
import type { RsaJsonWebKeyParameters } from "../../../jwk/rsa/rsa.jsonwebkey.parameters.ts";
import type { AESGCMKWJsonWebEncryptionHeaderParameters } from "./aesgcmkw.jsonwebencryption.header.parameters.ts";
import { AESGCMKWKeyManagementBackend } from "./aesgcmkw.key-management.backend.ts";

vi.mock(import("node:crypto"), async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, randomBytes: vi.fn() };
});

const invalidIVs: any[] = [
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

const invalidTags: any[] = [
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

describe("AES GCM Key Wrap Key Management Backend", () => {
  const contentEncryptionKey = Buffer.from("AAECAwQFBgcICQoLDA0ODw", "base64url");

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

  beforeEach(() => {
    vi.mocked(crypto.randomBytes).mockImplementation((size, cb) =>
      cb(null, size === 12 ? Buffer.alloc(12, 0x00) : Buffer.from([...Array.from({ length: size }).keys()])),
    );
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  describe("A128GCMKW", () => {
    const backend = new AESGCMKWKeyManagementBackend("A128GCMKW");

    const encryptedKey = Buffer.from("SdeFUJ2eoIvrgHBjbIy-kg", "base64url");

    const jsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({ k: "AAECAwQFBgcICQoLDA0ODw", kty: "oct" });

    let wrapHeader: JsonWebEncryptionHeader;
    let unwrapHeader: JsonWebEncryptionHeader<AESGCMKWJsonWebEncryptionHeaderParameters>;

    const wrongAlgJsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
      alg: "HS256",
      k: "AAECAwQFBgcICQoLDA0ODw",
      kty: "oct",
    });

    const badSizeJsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
      k: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX",
      kty: "oct",
    });

    const wrongEncryptedKey = Buffer.from("2wIQiLNIIiuLS0gt-8cryQ", "base64url");
    const wrongJsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
      k: "bSc_THqy4KVV6mwfYr7t4Q",
      kty: "oct",
    });

    const wrongInitializationVectorHeader = new JsonWebEncryptionHeader<AESGCMKWJsonWebEncryptionHeaderParameters>({
      alg: "A128GCMKW",
      enc: "A128GCM",
      iv: "AAECAwQFBgcICQoL",
      tag: "2uP2NZK_g9tW5Sh66ALzjg",
    });

    const wrongAuthenticationTagHeader = new JsonWebEncryptionHeader<AESGCMKWJsonWebEncryptionHeaderParameters>({
      alg: "A128GCMKW",
      enc: "A128GCM",
      iv: "AAAAAAAAAAAAAAAA",
      tag: "tmWkYioF468MBsE7x8EjWQ",
    });

    beforeEach(() => {
      wrapHeader = new JsonWebEncryptionHeader({ alg: "A128GCMKW", enc: "A128GCM" });
      unwrapHeader = new JsonWebEncryptionHeader({
        alg: "A128GCMKW",
        enc: "A128GCM",
        iv: "AAAAAAAAAAAAAAAA",
        tag: "2uP2NZK_g9tW5Sh66ALzjg",
      });
    });

    describe("wrap()", () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the Key Management Algorithm.', async () => {
        const error = new InvalidJsonWebKeyError(
          "The provided JSON Web Key cannot be used by the Key Management Algorithm.",
        );

        await expect(backend.wrap(contentEncryptionKey, wrongAlgJsonWebKey, wrapHeader)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        const error = new InvalidJsonWebKeyError('The Key Management Algorithm only accepts "oct" JSON Web Keys.');
        await expect(backend.wrap(contentEncryptionKey, wrongKtyJsonWebKey as any, wrapHeader)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length different than required.', async () => {
        const error = new InvalidJsonWebKeyError('The JSON Web Key Parameter "k" must be 128 bits.');
        await expect(backend.wrap(contentEncryptionKey, badSizeJsonWebKey, wrapHeader)).rejects.toThrow(error);
      });

      it("should wrap the provided Content Encryption Key.", async () => {
        await expect(backend.wrap(contentEncryptionKey, jsonWebKey, wrapHeader)).resolves.toStrictEqual(encryptedKey);
        expect(wrapHeader).toStrictEqual(unwrapHeader);
      });
    });

    describe("unwrap()", () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the Key Management Algorithm.', async () => {
        const error = new InvalidJsonWebKeyError(
          "The provided JSON Web Key cannot be used by the Key Management Algorithm.",
        );

        await expect(backend.unwrap(encryptedKey, wrongAlgJsonWebKey, unwrapHeader)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        const error = new InvalidJsonWebKeyError('The Key Management Algorithm only accepts "oct" JSON Web Keys.');
        await expect(backend.unwrap(encryptedKey, wrongKtyJsonWebKey as any, unwrapHeader)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length different than required.', async () => {
        const error = new InvalidJsonWebKeyError('The JSON Web Key Parameter "k" must be 128 bits.');
        await expect(backend.unwrap(encryptedKey, badSizeJsonWebKey, unwrapHeader)).rejects.toThrow(error);
      });

      it.each(invalidIVs)(
        'should throw when the provided JOSE Header Parameter "iv" is invalid.',
        async (initializationVector) => {
          Reflect.set(unwrapHeader.parameters, "iv", initializationVector);
          const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "iv".');
          await expect(backend.unwrap(encryptedKey, jsonWebKey, unwrapHeader)).rejects.toThrow(error);
        },
      );

      it.each(invalidTags)(
        'should throw when the provided JOSE Header Parameter "tag" is invalid.',
        async (authenticationTag) => {
          Reflect.set(unwrapHeader.parameters, "tag", authenticationTag);
          const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "tag".');
          await expect(backend.unwrap(encryptedKey, jsonWebKey, unwrapHeader)).rejects.toThrow(error);
        },
      );

      it("should throw when the provided Encrypted Key is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
        await expect(backend.unwrap(wrongEncryptedKey, jsonWebKey, unwrapHeader)).rejects.toThrow(error);
      });

      it("should throw when the provided JSON Web Key is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
        await expect(backend.unwrap(encryptedKey, wrongJsonWebKey, unwrapHeader)).rejects.toThrow(error);
      });

      it('should throw when providing the wrong JSON Web Encryption Header Parameter "iv".', async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
        await expect(backend.unwrap(encryptedKey, jsonWebKey, wrongInitializationVectorHeader)).rejects.toThrow(error);
      });

      it('should throw when providing the wrong JSON Web Encryption Header Parameter "tag".', async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
        await expect(backend.unwrap(encryptedKey, jsonWebKey, wrongAuthenticationTagHeader)).rejects.toThrow(error);
      });

      it("should unwrap the provided Encrypted Key.", async () => {
        await expect(backend.unwrap(encryptedKey, jsonWebKey, unwrapHeader)).resolves.toStrictEqual(
          contentEncryptionKey,
        );
      });
    });

    describe("generateContentEncryptionKey()", () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the Key Management Algorithm.', async () => {
        const error = new InvalidJsonWebKeyError(
          "The provided JSON Web Key cannot be used by the Key Management Algorithm.",
        );

        await expect(backend.generateContentEncryptionKey(wrongAlgJsonWebKey, wrapHeader)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        const error = new InvalidJsonWebKeyError('The Key Management Algorithm only accepts "oct" JSON Web Keys.');
        await expect(backend.generateContentEncryptionKey(wrongKtyJsonWebKey as any, wrapHeader)).rejects.toThrow(
          error,
        );
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length different than required.', async () => {
        const error = new InvalidJsonWebKeyError('The JSON Web Key Parameter "k" must be 128 bits.');
        await expect(backend.generateContentEncryptionKey(badSizeJsonWebKey, wrapHeader)).rejects.toThrow(error);
      });

      it("should generate a Content Encryption Key.", async () => {
        await expect(backend.generateContentEncryptionKey(jsonWebKey, wrapHeader)).resolves.toStrictEqual(
          contentEncryptionKey,
        );
      });
    });
  });

  describe("A192GCMKW", () => {
    const backend = new AESGCMKWKeyManagementBackend("A192GCMKW");

    const encryptedKey = Buffer.from("2wIQiLNIIiuLS0gt-8cryQ", "base64url");

    const jsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
      k: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX",
      kty: "oct",
    });

    let wrapHeader: JsonWebEncryptionHeader;
    let unwrapHeader: JsonWebEncryptionHeader<AESGCMKWJsonWebEncryptionHeaderParameters>;

    const wrongAlgJsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
      alg: "HS256",
      k: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX",
      kty: "oct",
    });

    const badSizeJsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
      k: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
      kty: "oct",
    });

    const wrongEncryptedKey = Buffer.from("Dr233bEphboAoaM-FCGflg", "base64url");
    const wrongJsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
      k: "zaexL6bBC4lhxS1S6OEH0V6wlP1toJhh",
      kty: "oct",
    });

    const wrongInitializationVectorHeader = new JsonWebEncryptionHeader<AESGCMKWJsonWebEncryptionHeaderParameters>({
      alg: "A192GCMKW",
      enc: "A128GCM",
      iv: "AAECAwQFBgcICQoL",
      tag: "eUtKT7fcX5HyikEV1IHP2Q",
    });

    const wrongAuthenticationTagHeader = new JsonWebEncryptionHeader<AESGCMKWJsonWebEncryptionHeaderParameters>({
      alg: "A192GCMKW",
      enc: "A128GCM",
      iv: "AAAAAAAAAAAAAAAA",
      tag: "tmWkYioF468MBsE7x8EjWQ",
    });

    beforeEach(() => {
      wrapHeader = new JsonWebEncryptionHeader({ alg: "A192GCMKW", enc: "A128GCM" });
      unwrapHeader = new JsonWebEncryptionHeader({
        alg: "A192GCMKW",
        enc: "A128GCM",
        iv: "AAAAAAAAAAAAAAAA",
        tag: "eUtKT7fcX5HyikEV1IHP2Q",
      });
    });

    describe("wrap()", () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the Key Management Algorithm.', async () => {
        const error = new InvalidJsonWebKeyError(
          "The provided JSON Web Key cannot be used by the Key Management Algorithm.",
        );

        await expect(backend.wrap(contentEncryptionKey, wrongAlgJsonWebKey, wrapHeader)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        const error = new InvalidJsonWebKeyError('The Key Management Algorithm only accepts "oct" JSON Web Keys.');
        await expect(backend.wrap(contentEncryptionKey, wrongKtyJsonWebKey as any, wrapHeader)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length different than required.', async () => {
        const error = new InvalidJsonWebKeyError('The JSON Web Key Parameter "k" must be 192 bits.');
        await expect(backend.wrap(contentEncryptionKey, badSizeJsonWebKey, wrapHeader)).rejects.toThrow(error);
      });

      it("should wrap the provided Content Encryption Key.", async () => {
        await expect(backend.wrap(contentEncryptionKey, jsonWebKey, wrapHeader)).resolves.toStrictEqual(encryptedKey);
        expect(wrapHeader).toStrictEqual(unwrapHeader);
      });
    });

    describe("unwrap()", () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the Key Management Algorithm.', async () => {
        const error = new InvalidJsonWebKeyError(
          "The provided JSON Web Key cannot be used by the Key Management Algorithm.",
        );

        await expect(backend.unwrap(encryptedKey, wrongAlgJsonWebKey, unwrapHeader)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        const error = new InvalidJsonWebKeyError('The Key Management Algorithm only accepts "oct" JSON Web Keys.');
        await expect(backend.unwrap(encryptedKey, wrongKtyJsonWebKey as any, unwrapHeader)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length different than required.', async () => {
        const error = new InvalidJsonWebKeyError('The JSON Web Key Parameter "k" must be 192 bits.');
        await expect(backend.unwrap(encryptedKey, badSizeJsonWebKey, unwrapHeader)).rejects.toThrow(error);
      });

      it.each(invalidIVs)(
        'should throw when the provided JOSE Header Parameter "iv" is invalid.',
        async (initializationVector) => {
          Reflect.set(unwrapHeader.parameters, "iv", initializationVector);
          const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "iv".');
          await expect(backend.unwrap(encryptedKey, jsonWebKey, unwrapHeader)).rejects.toThrow(error);
        },
      );

      it.each(invalidTags)(
        'should throw when the provided JOSE Header Parameter "tag" is invalid.',
        async (authenticationTag) => {
          Reflect.set(unwrapHeader.parameters, "tag", authenticationTag);
          const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "tag".');
          await expect(backend.unwrap(encryptedKey, jsonWebKey, unwrapHeader)).rejects.toThrow(error);
        },
      );

      it("should throw when the provided Encrypted Key is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
        await expect(backend.unwrap(wrongEncryptedKey, jsonWebKey, unwrapHeader)).rejects.toThrow(error);
      });

      it("should throw when the provided JSON Web Key is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
        await expect(backend.unwrap(encryptedKey, wrongJsonWebKey, unwrapHeader)).rejects.toThrow(error);
      });

      it('should throw when providing the wrong JSON Web Encryption Header Parameter "iv".', async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
        await expect(backend.unwrap(encryptedKey, jsonWebKey, wrongInitializationVectorHeader)).rejects.toThrow(error);
      });

      it('should throw when providing the wrong JSON Web Encryption Header Parameter "tag".', async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
        await expect(backend.unwrap(encryptedKey, jsonWebKey, wrongAuthenticationTagHeader)).rejects.toThrow(error);
      });

      it("should unwrap the provided Encrypted Key.", async () => {
        await expect(backend.unwrap(encryptedKey, jsonWebKey, unwrapHeader)).resolves.toStrictEqual(
          contentEncryptionKey,
        );
      });
    });

    describe("generateContentEncryptionKey()", () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the Key Management Algorithm.', async () => {
        const error = new InvalidJsonWebKeyError(
          "The provided JSON Web Key cannot be used by the Key Management Algorithm.",
        );

        await expect(backend.generateContentEncryptionKey(wrongAlgJsonWebKey, wrapHeader)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        const error = new InvalidJsonWebKeyError('The Key Management Algorithm only accepts "oct" JSON Web Keys.');
        await expect(backend.generateContentEncryptionKey(wrongKtyJsonWebKey as any, wrapHeader)).rejects.toThrow(
          error,
        );
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length different than required.', async () => {
        const error = new InvalidJsonWebKeyError('The JSON Web Key Parameter "k" must be 192 bits.');
        await expect(backend.generateContentEncryptionKey(badSizeJsonWebKey, wrapHeader)).rejects.toThrow(error);
      });

      it("should generate a Content Encryption Key.", async () => {
        await expect(backend.generateContentEncryptionKey(jsonWebKey, wrapHeader)).resolves.toStrictEqual(
          contentEncryptionKey,
        );
      });
    });
  });

  describe("A256GCMKW", () => {
    const backend = new AESGCMKWKeyManagementBackend("A256GCMKW");

    const encryptedKey = Buffer.from("Dr233bEphboAoaM-FCGflg", "base64url");

    const jsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
      k: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
      kty: "oct",
    });

    let wrapHeader: JsonWebEncryptionHeader;
    let unwrapHeader: JsonWebEncryptionHeader<AESGCMKWJsonWebEncryptionHeaderParameters>;

    const wrongAlgJsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
      alg: "HS256",
      k: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
      kty: "oct",
    });

    const badSizeJsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
      k: "AAECAwQFBgcICQoLDA0ODw",
      kty: "oct",
    });

    const wrongEncryptedKey = Buffer.from("SdeFUJ2eoIvrgHBjbIy-kg", "base64url");
    const wrongJsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
      k: "kIIor71zWjtNVXzalbKbjMU8whvBKQADD3IDRSh6Y7s",
      kty: "oct",
    });

    const wrongInitializationVectorHeader = new JsonWebEncryptionHeader<AESGCMKWJsonWebEncryptionHeaderParameters>({
      alg: "A256GCMKW",
      enc: "A128GCM",
      iv: "AAECAwQFBgcICQoL",
      tag: "KmK4cS6zJo9GwEweS9DtQA",
    });

    const wrongAuthenticationTagHeader = new JsonWebEncryptionHeader<AESGCMKWJsonWebEncryptionHeaderParameters>({
      alg: "A256GCMKW",
      enc: "A128GCM",
      iv: "AAAAAAAAAAAAAAAA",
      tag: "tmWkYioF468MBsE7x8EjWQ",
    });

    beforeEach(() => {
      wrapHeader = new JsonWebEncryptionHeader({ alg: "A256GCMKW", enc: "A128GCM" });
      unwrapHeader = new JsonWebEncryptionHeader({
        alg: "A256GCMKW",
        enc: "A128GCM",
        iv: "AAAAAAAAAAAAAAAA",
        tag: "KmK4cS6zJo9GwEweS9DtQA",
      });
    });

    describe("wrap()", () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the Key Management Algorithm.', async () => {
        const error = new InvalidJsonWebKeyError(
          "The provided JSON Web Key cannot be used by the Key Management Algorithm.",
        );

        await expect(backend.wrap(contentEncryptionKey, wrongAlgJsonWebKey, wrapHeader)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        const error = new InvalidJsonWebKeyError('The Key Management Algorithm only accepts "oct" JSON Web Keys.');
        await expect(backend.wrap(contentEncryptionKey, wrongKtyJsonWebKey as any, wrapHeader)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length different than required.', async () => {
        const error = new InvalidJsonWebKeyError('The JSON Web Key Parameter "k" must be 256 bits.');
        await expect(backend.wrap(contentEncryptionKey, badSizeJsonWebKey, wrapHeader)).rejects.toThrow(error);
      });

      it("should wrap the provided Content Encryption Key.", async () => {
        await expect(backend.wrap(contentEncryptionKey, jsonWebKey, wrapHeader)).resolves.toStrictEqual(encryptedKey);
        expect(wrapHeader).toStrictEqual(unwrapHeader);
      });
    });

    describe("unwrap()", () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the Key Management Algorithm.', async () => {
        const error = new InvalidJsonWebKeyError(
          "The provided JSON Web Key cannot be used by the Key Management Algorithm.",
        );

        await expect(backend.unwrap(encryptedKey, wrongAlgJsonWebKey, unwrapHeader)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        const error = new InvalidJsonWebKeyError('The Key Management Algorithm only accepts "oct" JSON Web Keys.');
        await expect(backend.unwrap(encryptedKey, wrongKtyJsonWebKey as any, unwrapHeader)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length different than required.', async () => {
        const error = new InvalidJsonWebKeyError('The JSON Web Key Parameter "k" must be 256 bits.');
        await expect(backend.unwrap(encryptedKey, badSizeJsonWebKey, unwrapHeader)).rejects.toThrow(error);
      });

      it.each(invalidIVs)(
        'should throw when the provided JOSE Header Parameter "iv" is invalid.',
        async (initializationVector) => {
          Reflect.set(unwrapHeader.parameters, "iv", initializationVector);
          const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "iv".');
          await expect(backend.unwrap(encryptedKey, jsonWebKey, unwrapHeader)).rejects.toThrow(error);
        },
      );

      it.each(invalidTags)(
        'should throw when the provided JOSE Header Parameter "tag" is invalid.',
        async (authenticationTag) => {
          Reflect.set(unwrapHeader.parameters, "tag", authenticationTag);
          const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "tag".');
          await expect(backend.unwrap(encryptedKey, jsonWebKey, unwrapHeader)).rejects.toThrow(error);
        },
      );

      it("should throw when the provided Encrypted Key is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
        await expect(backend.unwrap(wrongEncryptedKey, jsonWebKey, unwrapHeader)).rejects.toThrow(error);
      });

      it("should throw when the provided JSON Web Key is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
        await expect(backend.unwrap(encryptedKey, wrongJsonWebKey, unwrapHeader)).rejects.toThrow(error);
      });

      it('should throw when providing the wrong JSON Web Encryption Header Parameter "iv".', async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
        await expect(backend.unwrap(encryptedKey, jsonWebKey, wrongInitializationVectorHeader)).rejects.toThrow(error);
      });

      it('should throw when providing the wrong JSON Web Encryption Header Parameter "tag".', async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
        await expect(backend.unwrap(encryptedKey, jsonWebKey, wrongAuthenticationTagHeader)).rejects.toThrow(error);
      });

      it("should unwrap the provided Encrypted Key.", async () => {
        await expect(backend.unwrap(encryptedKey, jsonWebKey, unwrapHeader)).resolves.toStrictEqual(
          contentEncryptionKey,
        );
      });
    });

    describe("generateContentEncryptionKey()", () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the Key Management Algorithm.', async () => {
        const error = new InvalidJsonWebKeyError(
          "The provided JSON Web Key cannot be used by the Key Management Algorithm.",
        );

        await expect(backend.generateContentEncryptionKey(wrongAlgJsonWebKey, wrapHeader)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        const error = new InvalidJsonWebKeyError('The Key Management Algorithm only accepts "oct" JSON Web Keys.');
        await expect(backend.generateContentEncryptionKey(wrongKtyJsonWebKey as any, wrapHeader)).rejects.toThrow(
          error,
        );
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length different than required.', async () => {
        const error = new InvalidJsonWebKeyError('The JSON Web Key Parameter "k" must be 256 bits.');
        await expect(backend.generateContentEncryptionKey(badSizeJsonWebKey, wrapHeader)).rejects.toThrow(error);
      });

      it("should generate a Content Encryption Key.", async () => {
        await expect(backend.generateContentEncryptionKey(jsonWebKey, wrapHeader)).resolves.toStrictEqual(
          contentEncryptionKey,
        );
      });
    });
  });
});
