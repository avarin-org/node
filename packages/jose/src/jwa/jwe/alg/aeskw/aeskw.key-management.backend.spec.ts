import { Buffer } from "node:buffer";
import * as crypto from "node:crypto";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { InvalidJsonWebEncryptionError } from "../../../../errors/invalid-jsonwebencryption.error.ts";
import { InvalidJsonWebKeyError } from "../../../../errors/invalid-jsonwebkey.error.ts";
import { JsonWebEncryptionHeader } from "../../../../jwe/header/jsonwebencryption.header.ts";
import { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import type { OctetSequenceJsonWebKeyParameters } from "../../../jwk/oct/octet-sequence.jsonwebkey.parameters.ts";
import type { RsaJsonWebKeyParameters } from "../../../jwk/rsa/rsa.jsonwebkey.parameters.ts";
import { AESKWKeyManagementBackend } from "./aeskw.key-management.backend.ts";

vi.mock(import("node:crypto"), async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, randomBytes: vi.fn() };
});

describe("AES Key Wrap Key Management Backend", () => {
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
      cb(null, Buffer.from([...Array.from({ length: size }).keys()])),
    );
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  describe("A128KW", () => {
    const backend = new AESKWKeyManagementBackend("A128KW");

    const encryptedKey = Buffer.from("k1o-sQHDSt0CXhcLRv8Nsj5cL66Mj4Nw", "base64url");

    const jsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({ k: "AAECAwQFBgcICQoLDA0ODw", kty: "oct" });

    const header = new JsonWebEncryptionHeader({ alg: "A128KW", enc: "A128GCM" });

    const wrongAlgJsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
      alg: "HS256",
      k: "AAECAwQFBgcICQoLDA0ODw",
      kty: "oct",
    });

    const badSizeJsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
      k: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX",
      kty: "oct",
    });

    const wrongEncryptedKey = Buffer.from("VJBm6T4_p5MNZCsW4lu050IbEWJpedBF", "base64url");

    const wrongJsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
      k: "bSc_THqy4KVV6mwfYr7t4Q",
      kty: "oct",
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

      it('should throw when the provided JSON Web Key Parameter "k" has length different than required.', async () => {
        const error = new InvalidJsonWebKeyError('The JSON Web Key Parameter "k" must be 128 bits.');
        await expect(backend.wrap(contentEncryptionKey, badSizeJsonWebKey, header)).rejects.toThrow(error);
      });

      it("should wrap the provided Content Encryption Key.", async () => {
        await expect(backend.wrap(contentEncryptionKey, jsonWebKey, header)).resolves.toStrictEqual(encryptedKey);
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

      it('should throw when the provided JSON Web Key Parameter "k" has length different than required.', async () => {
        const error = new InvalidJsonWebKeyError('The JSON Web Key Parameter "k" must be 128 bits.');
        await expect(backend.unwrap(encryptedKey, badSizeJsonWebKey, header)).rejects.toThrow(error);
      });

      it("should throw when the provided Encrypted Key is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
        await expect(backend.unwrap(wrongEncryptedKey, jsonWebKey, header)).rejects.toThrow(error);
      });

      it("should throw when the provided JSON Web Key is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
        await expect(backend.unwrap(encryptedKey, wrongJsonWebKey, header)).rejects.toThrow(error);
      });

      it("should unwrap the provided Encrypted Key.", async () => {
        await expect(backend.unwrap(encryptedKey, jsonWebKey, header)).resolves.toStrictEqual(contentEncryptionKey);
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

      it('should throw when the provided JSON Web Key Parameter "k" has length different than required.', async () => {
        const error = new InvalidJsonWebKeyError('The JSON Web Key Parameter "k" must be 128 bits.');
        await expect(backend.generateContentEncryptionKey(badSizeJsonWebKey, header)).rejects.toThrow(error);
      });

      it("should generate a Content Encryption Key.", async () => {
        await expect(backend.generateContentEncryptionKey(jsonWebKey, header)).resolves.toStrictEqual(
          contentEncryptionKey,
        );
      });
    });
  });

  describe("A192KW", () => {
    const backend = new AESKWKeyManagementBackend("A192KW");

    const encryptedKey = Buffer.from("VJBm6T4_p5MNZCsW4lu050IbEWJpedBF", "base64url");

    const jsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
      k: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX",
      kty: "oct",
    });

    const header = new JsonWebEncryptionHeader({ alg: "A192KW", enc: "A128GCM" });

    const wrongAlgJsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
      alg: "HS256",
      k: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX",
      kty: "oct",
    });

    const badSizeJsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
      k: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
      kty: "oct",
    });

    const wrongEncryptedKey = Buffer.from("jMS_7Kip8vOMiyg5Lx6PSz5aX9LyC9aI", "base64url");

    const wrongJsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
      k: "n16iBJM9W-JXIPjlLsoTfTcivlWrlIaW",
      kty: "oct",
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

      it('should throw when the provided JSON Web Key Parameter "k" has length different than required.', async () => {
        const error = new InvalidJsonWebKeyError('The JSON Web Key Parameter "k" must be 192 bits.');
        await expect(backend.wrap(contentEncryptionKey, badSizeJsonWebKey, header)).rejects.toThrow(error);
      });

      it("should wrap the provided Content Encryption Key.", async () => {
        await expect(backend.wrap(contentEncryptionKey, jsonWebKey, header)).resolves.toStrictEqual(encryptedKey);
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

      it('should throw when the provided JSON Web Key Parameter "k" has length different than required.', async () => {
        const error = new InvalidJsonWebKeyError('The JSON Web Key Parameter "k" must be 192 bits.');
        await expect(backend.unwrap(encryptedKey, badSizeJsonWebKey, header)).rejects.toThrow(error);
      });

      it("should throw when the provided Encrypted Key is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
        await expect(backend.unwrap(wrongEncryptedKey, jsonWebKey, header)).rejects.toThrow(error);
      });

      it("should throw when the provided JSON Web Key is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
        await expect(backend.unwrap(encryptedKey, wrongJsonWebKey, header)).rejects.toThrow(error);
      });

      it("should unwrap the provided Encrypted Key.", async () => {
        await expect(backend.unwrap(encryptedKey, jsonWebKey, header)).resolves.toStrictEqual(contentEncryptionKey);
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

      it('should throw when the provided JSON Web Key Parameter "k" has length different than required.', async () => {
        const error = new InvalidJsonWebKeyError('The JSON Web Key Parameter "k" must be 192 bits.');
        await expect(backend.generateContentEncryptionKey(badSizeJsonWebKey, header)).rejects.toThrow(error);
      });

      it("should generate a Content Encryption Key.", async () => {
        await expect(backend.generateContentEncryptionKey(jsonWebKey, header)).resolves.toStrictEqual(
          contentEncryptionKey,
        );
      });
    });
  });

  describe("A256KW", () => {
    const backend = new AESKWKeyManagementBackend("A256KW");

    const encryptedKey = Buffer.from("jMS_7Kip8vOMiyg5Lx6PSz5aX9LyC9aI", "base64url");

    const jsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
      k: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
      kty: "oct",
    });

    const header = new JsonWebEncryptionHeader({ alg: "A256KW", enc: "A128GCM" });

    const wrongAlgJsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
      alg: "HS256",
      k: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
      kty: "oct",
    });

    const badSizeJsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
      k: "AAECAwQFBgcICQoLDA0ODw",
      kty: "oct",
    });

    const wrongEncryptedKey = Buffer.from("k1o-sQHDSt0CXhcLRv8Nsj5cL66Mj4Nw", "base64url");

    const wrongJsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
      k: "ZlDHyJ4NcRBxFBbC_JL6csK-SXBWYZkDaIz_GoZy7Tw",
      kty: "oct",
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

      it('should throw when the provided JSON Web Key Parameter "k" has length different than required.', async () => {
        const error = new InvalidJsonWebKeyError('The JSON Web Key Parameter "k" must be 256 bits.');
        await expect(backend.wrap(contentEncryptionKey, badSizeJsonWebKey, header)).rejects.toThrow(error);
      });

      it("should wrap the provided Content Encryption Key.", async () => {
        await expect(backend.wrap(contentEncryptionKey, jsonWebKey, header)).resolves.toStrictEqual(encryptedKey);
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

      it('should throw when the provided JSON Web Key Parameter "k" has length different than required.', async () => {
        const error = new InvalidJsonWebKeyError('The JSON Web Key Parameter "k" must be 256 bits.');
        await expect(backend.unwrap(encryptedKey, badSizeJsonWebKey, header)).rejects.toThrow(error);
      });

      it("should throw when the provided Encrypted Key is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
        await expect(backend.unwrap(wrongEncryptedKey, jsonWebKey, header)).rejects.toThrow(error);
      });

      it("should throw when the provided JSON Web Key is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
        await expect(backend.unwrap(encryptedKey, wrongJsonWebKey, header)).rejects.toThrow(error);
      });

      it("should unwrap the provided Encrypted Key.", async () => {
        await expect(backend.unwrap(encryptedKey, jsonWebKey, header)).resolves.toStrictEqual(contentEncryptionKey);
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

      it('should throw when the provided JSON Web Key Parameter "k" has length different than required.', async () => {
        const error = new InvalidJsonWebKeyError('The JSON Web Key Parameter "k" must be 256 bits.');
        await expect(backend.generateContentEncryptionKey(badSizeJsonWebKey, header)).rejects.toThrow(error);
      });

      it("should generate a Content Encryption Key.", async () => {
        await expect(backend.generateContentEncryptionKey(jsonWebKey, header)).resolves.toStrictEqual(
          contentEncryptionKey,
        );
      });
    });
  });
});
