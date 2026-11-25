import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import { InvalidJsonWebEncryptionError } from "../../../../errors/invalid-jsonwebencryption.error.ts";
import { InvalidJsonWebKeyError } from "../../../../errors/invalid-jsonwebkey.error.ts";
import { JsonWebEncryptionHeader } from "../../../../jwe/header/jsonwebencryption.header.ts";
import { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import type { OctetSequenceJsonWebKeyParameters } from "../../../jwk/oct/octet-sequence.jsonwebkey.parameters.ts";
import type { RsaJsonWebKeyParameters } from "../../../jwk/rsa/rsa.jsonwebkey.parameters.ts";
import { DirKeyManagementBackend } from "./dir.key-management.backend.ts";

describe("Dir Key Management Backend", () => {
  const contentEncryptionKey = Buffer.from("AAECAwQFBgcICQoLDA0ODw", "base64url");

  describe("dir", () => {
    const backend = new DirKeyManagementBackend();

    const encryptedKey = Buffer.alloc(0);
    const jsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({ k: "AAECAwQFBgcICQoLDA0ODw", kty: "oct" });
    const header = new JsonWebEncryptionHeader({ alg: "dir", enc: "A128GCM" });

    const wrongAlgJsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
      alg: "HS256",
      k: "AAECAwQFBgcICQoLDA0ODw",
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

    const badSizeEncryptedKey = Buffer.from("AAECAwQFBgcICQoLDA0ODw", "base64url");

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

      it("should throw when the length of the Content Encryption Key is not supported by the Encryption Algorithm.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
        await expect(backend.unwrap(badSizeEncryptedKey, jsonWebKey, header)).rejects.toThrow(error);
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

      it("should generate a Content Encryption Key.", async () => {
        await expect(backend.generateContentEncryptionKey(jsonWebKey, header)).resolves.toStrictEqual(
          contentEncryptionKey,
        );
      });
    });
  });
});
