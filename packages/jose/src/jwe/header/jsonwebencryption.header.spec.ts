import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import { InvalidJoseHeaderError } from "../../errors/invalid-jose-header.error.ts";
import type { KeyManagementAlgorithm } from "../../jwa/jwe/alg/key-management-algorithm.type.ts";
import { KEY_MANAGEMENT_BACKEND_REGISTRY } from "../../jwa/jwe/alg/key-management.backend.registry.ts";
import { KeyManagementBackend } from "../../jwa/jwe/alg/key-management.backend.ts";
import type { ContentEncryptionAlgorithm } from "../../jwa/jwe/enc/content-encryption-algorithm.type.ts";
import { CONTENT_ENCRYPTION_BACKEND_REGISTRY } from "../../jwa/jwe/enc/content-encryption.backend.registry.ts";
import { ContentEncryptionBackend } from "../../jwa/jwe/enc/content-encryption.backend.ts";
import type { CompressionAlgorithm } from "../../jwa/jwe/zip/compression-algorithm.type.ts";
import { CompressionBackend } from "../../jwa/jwe/zip/compression.backend.ts";
import type { JsonWebEncryptionHeaderParameters } from "./jsonwebencryption.header.parameters.ts";
import { JsonWebEncryptionHeader } from "./jsonwebencryption.header.ts";

const invalidAlgs: any[] = [
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
  "a",
];

const invalidEncs: any[] = [
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
  "a",
];

const invalidZips: any[] = [
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
  "a",
];

const headerAlgorithms: [KeyManagementAlgorithm, ContentEncryptionAlgorithm][] =
  KEY_MANAGEMENT_BACKEND_REGISTRY.flatMap((keyManagementBackend) =>
    CONTENT_ENCRYPTION_BACKEND_REGISTRY.map((contentEncryptionBackend) => [
      keyManagementBackend.name,
      contentEncryptionBackend.name,
    ]),
  );

describe("JSON Web Encryption Header", () => {
  const parameters: JsonWebEncryptionHeaderParameters = {
    alg: "A128KW",
    enc: "A128CBC-HS256",
  };

  describe("constructor", () => {
    it.each(invalidAlgs)('should throw when the provided JOSE Header Parameter "alg" is invalid.', (alg) => {
      const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "alg".');
      expect(() => new JsonWebEncryptionHeader({ ...parameters, alg })).toThrow(error);
    });

    it.each(invalidEncs)('should throw when the provided JOSE Header Parameter "enc" is invalid.', (enc) => {
      const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "enc".');
      expect(() => new JsonWebEncryptionHeader({ ...parameters, enc })).toThrow(error);
    });

    it.each(invalidZips)('should throw when the provided JOSE Header Parameter "zip" is invalid.', (zip) => {
      const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "zip".');
      expect(() => new JsonWebEncryptionHeader({ ...parameters, zip })).toThrow(error);
    });

    it.each(headerAlgorithms)("should return a JSON Web Encryption Header.", (alg, enc) => {
      let header!: JsonWebEncryptionHeader;

      expect(() => (header = new JsonWebEncryptionHeader({ alg, enc }))).not.toThrow();

      expect(header.keyManagementBackend).toBeInstanceOf(KeyManagementBackend);
      expect(header.keyManagementBackend.name).toBe(alg);

      expect(header.contentEncryptionBackend).toBeInstanceOf(ContentEncryptionBackend);
      expect(header.contentEncryptionBackend.name).toBe(enc);

      expect(header.compressionBackend).toBeNull();

      expect(header.certificateChain).toBeNull();
      expect(header.jsonWebKey).toBeNull();
      expect(header.parameters).toStrictEqual({ alg, enc });
    });

    it.each(headerAlgorithms)("should return a JSON Web Encryption Header with a Compression Backend.", (alg, enc) => {
      let header!: JsonWebEncryptionHeader;

      expect(() => (header = new JsonWebEncryptionHeader({ alg, enc, zip: "DEF" }))).not.toThrow();

      expect(header.keyManagementBackend).toBeInstanceOf(KeyManagementBackend);
      expect(header.keyManagementBackend.name).toBe(alg);

      expect(header.contentEncryptionBackend).toBeInstanceOf(ContentEncryptionBackend);
      expect(header.contentEncryptionBackend.name).toBe(enc);

      expect(header.compressionBackend).toBeInstanceOf(CompressionBackend);
      expect(header.compressionBackend!.name).toBe<CompressionAlgorithm>("DEF");

      expect(header.certificateChain).toBeNull();
      expect(header.jsonWebKey).toBeNull();
      expect(header.parameters).toStrictEqual({ alg, enc, zip: "DEF" });
    });
  });
});
