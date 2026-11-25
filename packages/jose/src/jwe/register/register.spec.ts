import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import { AESGCMKWKeyManagementBackend } from "../../jwa/jwe/alg/aesgcmkw/aesgcmkw.key-management.backend.ts";
import { KEY_MANAGEMENT_BACKEND_REGISTRY } from "../../jwa/jwe/alg/key-management.backend.registry.ts";
import { KeyManagementBackend } from "../../jwa/jwe/alg/key-management.backend.ts";
import { AESGCMContentEncryptionBackend } from "../../jwa/jwe/enc/aesgcm/aesgcm.content-encryption.backend.ts";
import { CONTENT_ENCRYPTION_BACKEND_REGISTRY } from "../../jwa/jwe/enc/content-encryption.backend.registry.ts";
import { ContentEncryptionBackend } from "../../jwa/jwe/enc/content-encryption.backend.ts";
import { COMPRESSION_BACKEND_REGISTRY } from "../../jwa/jwe/zip/compression.backend.registry.ts";
import { CompressionBackend } from "../../jwa/jwe/zip/compression.backend.ts";
import { DEFCompressionBackend } from "../../jwa/jwe/zip/def/def.compression.backend.ts";
import type { JsonWebKey } from "../../jwk/jsonwebkey.ts";
import type { JsonWebEncryptionHeader } from "../header/jsonwebencryption.header.ts";
import { register } from "./register.ts";

class CustomKeyManagementBackend extends KeyManagementBackend {
  public constructor() {
    super("custom_alg");
  }
  public async wrap(
    _contentEncryptionKey: Buffer,
    _jsonWebKey: JsonWebKey,
    _header: JsonWebEncryptionHeader,
  ): Promise<Buffer> {
    throw new Error("Method not implemented.");
  }
  public async unwrap(
    _encryptedKey: Buffer,
    _jsonWebKey: JsonWebKey,
    _header: JsonWebEncryptionHeader,
  ): Promise<Buffer> {
    throw new Error("Method not implemented.");
  }
  public async generateContentEncryptionKey(
    _jsonWebKey: JsonWebKey,
    _header: JsonWebEncryptionHeader,
  ): Promise<Buffer> {
    throw new Error("Method not implemented.");
  }
}

class Custom2KeyManagementBackend extends KeyManagementBackend {
  public constructor() {
    super("custom_alg");
  }
  public async wrap(
    _contentEncryptionKey: Buffer,
    _jsonWebKey: JsonWebKey,
    _header: JsonWebEncryptionHeader,
  ): Promise<Buffer> {
    throw new Error("Method not implemented.");
  }
  public async unwrap(
    _encryptedKey: Buffer,
    _jsonWebKey: JsonWebKey,
    _header: JsonWebEncryptionHeader,
  ): Promise<Buffer> {
    throw new Error("Method not implemented.");
  }
  public async generateContentEncryptionKey(
    _jsonWebKey: JsonWebKey,
    _header: JsonWebEncryptionHeader,
  ): Promise<Buffer> {
    throw new Error("Method not implemented.");
  }
}

class CustomContentEncryptionBackend extends ContentEncryptionBackend {
  public constructor() {
    super("custom_enc", 256, 256);
  }
  public async encrypt(
    _plaintext: Buffer,
    _contentEncryptionKey: Buffer,
    _additionalAuthenticatedData: Buffer,
    _initializationVector: Buffer,
  ): Promise<[Buffer, Buffer]> {
    throw new Error("Method not implemented.");
  }
  public async decrypt(
    _ciphertext: Buffer,
    _contentEncryptionKey: Buffer,
    _additionalAuthenticatedData: Buffer,
    _initializationVector: Buffer,
    _authenticationTag: Buffer,
  ): Promise<Buffer> {
    throw new Error("Method not implemented.");
  }
}

class Custom2ContentEncryptionBackend extends ContentEncryptionBackend {
  public constructor() {
    super("custom_enc", 256, 256);
  }
  public async encrypt(
    _plaintext: Buffer,
    _contentEncryptionKey: Buffer,
    _additionalAuthenticatedData: Buffer,
    _initializationVector: Buffer,
  ): Promise<[Buffer, Buffer]> {
    throw new Error("Method not implemented.");
  }
  public async decrypt(
    _ciphertext: Buffer,
    _contentEncryptionKey: Buffer,
    _additionalAuthenticatedData: Buffer,
    _initializationVector: Buffer,
    _authenticationTag: Buffer,
  ): Promise<Buffer> {
    throw new Error("Method not implemented.");
  }
}

class CustomCompressionBackend extends CompressionBackend {
  public constructor() {
    super("custom_def");
  }
  public async compress(_plaintext: Buffer): Promise<Buffer> {
    throw new Error("Method not implemented.");
  }
  public async decompress(_plaintext: Buffer): Promise<Buffer> {
    throw new Error("Method not implemented.");
  }
}

class Custom2CompressionBackend extends CompressionBackend {
  public constructor() {
    super("custom_def");
  }
  public async compress(_plaintext: Buffer): Promise<Buffer> {
    throw new Error("Method not implemented.");
  }
  public async decompress(_plaintext: Buffer): Promise<Buffer> {
    throw new Error("Method not implemented.");
  }
}

const invalidJsonWebEncryptionBackends: any[] = [
  undefined,
  null,
  true,
  1,
  1.2,
  1n,
  "",
  Symbol("a"),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  {},
  [],
];

describe("register()", () => {
  it.each(invalidJsonWebEncryptionBackends)(
    "should throw when the provided class is not a JSON Web Encryption Backend.",
    (backend) => {
      const error = new TypeError("The provided JSON Web Encryption Backend is invalid.");
      expect(() => register(backend)).toThrow(error);
    },
  );

  it("should throw when the provided Key Management Backend already registered.", () => {
    const error = new TypeError("The provided Key Management Backend is already registered.");
    expect(() => register(new AESGCMKWKeyManagementBackend("A128GCMKW"))).toThrow(error);
  });

  it("should register the provided Key Management Backend into the Registry.", () => {
    expect(() => register(new CustomKeyManagementBackend())).not.toThrow();
    expect(KEY_MANAGEMENT_BACKEND_REGISTRY).toContainEqual(expect.any(CustomKeyManagementBackend));
  });

  it.each([CustomKeyManagementBackend, Custom2KeyManagementBackend])(
    "should throw when the provided Key Management is already registered.",
    (Backend) => {
      const error = new TypeError("The provided Key Management Backend is already registered.");
      expect(() => register(new Backend())).toThrow(error);
    },
  );

  it("should throw when the provided Content Encryption Backend already registered.", () => {
    const error = new TypeError("The provided Content Encryption Backend is already registered.");
    expect(() => register(new AESGCMContentEncryptionBackend("A128GCM"))).toThrow(error);
  });

  it("should register the provided Content Encryption Backend into the Registry.", () => {
    expect(() => register(new CustomContentEncryptionBackend())).not.toThrow();
    expect(CONTENT_ENCRYPTION_BACKEND_REGISTRY).toContainEqual(expect.any(CustomContentEncryptionBackend));
  });

  it.each([CustomContentEncryptionBackend, Custom2ContentEncryptionBackend])(
    "should throw when the provided Content Encryption is already registered.",
    (Backend) => {
      const error = new TypeError("The provided Content Encryption Backend is already registered.");
      expect(() => register(new Backend())).toThrow(error);
    },
  );

  it("should throw when the provided Compression Backend already registered.", () => {
    const error = new TypeError("The provided Compression Backend is already registered.");
    expect(() => register(new DEFCompressionBackend())).toThrow(error);
  });

  it("should register the provided Compression Backend into the Registry.", () => {
    expect(() => register(new CustomCompressionBackend())).not.toThrow();
    expect(COMPRESSION_BACKEND_REGISTRY).toContainEqual(expect.any(CustomCompressionBackend));
  });

  it.each([CustomCompressionBackend, Custom2CompressionBackend])(
    "should throw when the provided Compression is already registered.",
    (Backend) => {
      const error = new TypeError("The provided Compression Backend is already registered.");
      expect(() => register(new Backend())).toThrow(error);
    },
  );
});
