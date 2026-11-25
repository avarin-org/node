import { Buffer } from "node:buffer";
import * as crypto from "node:crypto";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { InvalidJsonWebEncryptionError } from "../../../../errors/invalid-jsonwebencryption.error.ts";
import { AESCBCContentEncryptionBackend } from "./aescbc.content-encryption.backend.ts";

vi.mock(import("node:crypto"), async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, randomBytes: vi.fn() };
});

describe("AES CBC Content Encryption Backend", () => {
  const plaintext = Buffer.from("Super secret message.", "utf8");
  const additionalAuthenticatedData = Buffer.alloc(0);
  const initializationVector = Buffer.from("AAAAAAAAAAAAAAAAAAAAAA", "base64url");

  const badLengthInitializationVector = Buffer.from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "base64url");

  const badCiphertext = Buffer.from("id4pfaiMSfjGeChypGzl5jV4_RtyN5qShHO9Djyaz2k", "base64url");
  const badInitializationVector = Buffer.from("8ugOjchaHMDwOcPII2BWhw", "base64url");
  const badAdditionalAuthenticatedData = Buffer.alloc(1);

  beforeEach(() => {
    vi.mocked(crypto.randomBytes).mockImplementation((size, cb) => cb(null, Buffer.alloc(size, 0x00)));
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  describe("A128CBC-HS256", () => {
    const backend = new AESCBCContentEncryptionBackend("A128CBC-HS256");

    const ciphertext = Buffer.from("4i7-_mXyLjinjA3Q9fx7shLG1sHyDC6SQ_9OVtZzU-M", "base64url");
    const contentEncryptionKey = Buffer.from("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", "base64url");
    const authenticationTag = Buffer.from("DAVUFw9ZARV1ux5Y3Vi6CA", "base64url");

    const badLengthContentEncryptionKey = Buffer.from("1E8iEkKORbJq3o4Iq3JuxQ", "base64url");
    const badContentEncryptionKey = Buffer.from("6KZLfdkyIkYagFaaElP9xhZE7jO6wvuD_XTwx6oASVk", "base64url");
    const badAuthenticationTag = Buffer.from("XBNd9px4iqzpAu_mKBzeng", "base64url");

    describe("encrypt()", () => {
      it("should throw when the length of the provided Content Encryption Key is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided Content Encryption Key is invalid.");

        await expect(
          backend.encrypt(plaintext, badLengthContentEncryptionKey, additionalAuthenticatedData, initializationVector),
        ).rejects.toThrow(error);
      });

      it("should throw when the length of the provided Initialization Vector is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided Initialization Vector is invalid.");

        await expect(
          backend.encrypt(plaintext, contentEncryptionKey, additionalAuthenticatedData, badLengthInitializationVector),
        ).rejects.toThrow(error);
      });

      it("should encrypt the provided Plaintext.", async () => {
        await expect(
          backend.encrypt(plaintext, contentEncryptionKey, additionalAuthenticatedData, initializationVector),
        ).resolves.toStrictEqual([ciphertext, authenticationTag]);
      });
    });

    describe("decrypt()", () => {
      it("should throw when the length of the provided Content Encryption Key is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided Content Encryption Key is invalid.");

        await expect(
          backend.decrypt(
            ciphertext,
            badLengthContentEncryptionKey,
            additionalAuthenticatedData,
            initializationVector,
            authenticationTag,
          ),
        ).rejects.toThrow(error);
      });

      it("should throw when the length of the provided Initialization Vector is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided Initialization Vector is invalid.");

        await expect(
          backend.decrypt(
            ciphertext,
            contentEncryptionKey,
            additionalAuthenticatedData,
            badLengthInitializationVector,
            authenticationTag,
          ),
        ).rejects.toThrow(error);
      });

      it("should throw when the provided Ciphertext is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");

        await expect(
          backend.decrypt(
            badCiphertext,
            contentEncryptionKey,
            additionalAuthenticatedData,
            initializationVector,
            authenticationTag,
          ),
        ).rejects.toThrow(error);
      });

      it("should throw when the provided Content Encryption Key is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");

        await expect(
          backend.decrypt(
            ciphertext,
            badContentEncryptionKey,
            additionalAuthenticatedData,
            initializationVector,
            authenticationTag,
          ),
        ).rejects.toThrow(error);
      });

      it("should throw when the provided Additional Authenticated Data is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");

        await expect(
          backend.decrypt(
            ciphertext,
            contentEncryptionKey,
            badAdditionalAuthenticatedData,
            initializationVector,
            authenticationTag,
          ),
        ).rejects.toThrow(error);
      });

      it("should throw when the provided Initialization Vector is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");

        await expect(
          backend.decrypt(
            ciphertext,
            contentEncryptionKey,
            additionalAuthenticatedData,
            badInitializationVector,
            authenticationTag,
          ),
        ).rejects.toThrow(error);
      });

      it("should throw when the provided Authentication Tag is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");

        await expect(
          backend.decrypt(
            ciphertext,
            contentEncryptionKey,
            additionalAuthenticatedData,
            initializationVector,
            badAuthenticationTag,
          ),
        ).rejects.toThrow(error);
      });

      it("should decrypt the provided Ciphertext.", async () => {
        await expect(
          backend.decrypt(
            ciphertext,
            contentEncryptionKey,
            additionalAuthenticatedData,
            initializationVector,
            authenticationTag,
          ),
        ).resolves.toStrictEqual(plaintext);
      });
    });

    describe("generateInitializationVector()", () => {
      it("should generate an Initialization Vector.", async () => {
        await expect(backend.generateInitializationVector()).resolves.toStrictEqual(initializationVector);
      });
    });
  });

  describe("A192CBC-HS384", () => {
    const backend = new AESCBCContentEncryptionBackend("A192CBC-HS384");

    const ciphertext = Buffer.from("Rzc-nCIBUZsK8HAjAB4KA60VXWjmnCemM30Poujlt7o", "base64url");
    const contentEncryptionKey = Buffer.from(
      "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v",
      "base64url",
    );

    const authenticationTag = Buffer.from("ckxgS8jLleWk4U7_s2z8-JdJdzcOV4ON", "base64url");

    const badLengthContentEncryptionKey = Buffer.from("86Mpm3txpeKWQqIMSilkUeNo8sdvmXKB", "base64url");
    const badContentEncryptionKey = Buffer.from(
      "PfBSi7vja_wLS85-hUSg7sBWRyCLdN6QcIzRPnbatw4oaDdhW16goQrYvfWFlNV4",
      "base64url",
    );

    const badAuthenticationTag = Buffer.from("dpOCso84OhUib5vEJygn6jRKRVeexcA4", "base64url");

    describe("encrypt()", () => {
      it("should throw when the length of the provided Content Encryption Key is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided Content Encryption Key is invalid.");

        await expect(
          backend.encrypt(plaintext, badLengthContentEncryptionKey, additionalAuthenticatedData, initializationVector),
        ).rejects.toThrow(error);
      });

      it("should throw when the length of the provided Initialization Vector is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided Initialization Vector is invalid.");

        await expect(
          backend.encrypt(plaintext, contentEncryptionKey, additionalAuthenticatedData, badLengthInitializationVector),
        ).rejects.toThrow(error);
      });

      it("should encrypt the provided Plaintext.", async () => {
        await expect(
          backend.encrypt(plaintext, contentEncryptionKey, additionalAuthenticatedData, initializationVector),
        ).resolves.toStrictEqual([ciphertext, authenticationTag]);
      });
    });

    describe("decrypt()", () => {
      it("should throw when the length of the provided Content Encryption Key is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided Content Encryption Key is invalid.");

        await expect(
          backend.decrypt(
            ciphertext,
            badLengthContentEncryptionKey,
            additionalAuthenticatedData,
            initializationVector,
            authenticationTag,
          ),
        ).rejects.toThrow(error);
      });

      it("should throw when the length of the provided Initialization Vector is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided Initialization Vector is invalid.");

        await expect(
          backend.decrypt(
            ciphertext,
            contentEncryptionKey,
            additionalAuthenticatedData,
            badLengthInitializationVector,
            authenticationTag,
          ),
        ).rejects.toThrow(error);
      });

      it("should throw when the provided Ciphertext is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");

        await expect(
          backend.decrypt(
            badCiphertext,
            contentEncryptionKey,
            additionalAuthenticatedData,
            initializationVector,
            authenticationTag,
          ),
        ).rejects.toThrow(error);
      });

      it("should throw when the provided Content Encryption Key is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");

        await expect(
          backend.decrypt(
            ciphertext,
            badContentEncryptionKey,
            additionalAuthenticatedData,
            initializationVector,
            authenticationTag,
          ),
        ).rejects.toThrow(error);
      });

      it("should throw when the provided Additional Authenticated Data is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");

        await expect(
          backend.decrypt(
            ciphertext,
            contentEncryptionKey,
            badAdditionalAuthenticatedData,
            initializationVector,
            authenticationTag,
          ),
        ).rejects.toThrow(error);
      });

      it("should throw when the provided Initialization Vector is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");

        await expect(
          backend.decrypt(
            ciphertext,
            contentEncryptionKey,
            additionalAuthenticatedData,
            badInitializationVector,
            authenticationTag,
          ),
        ).rejects.toThrow(error);
      });

      it("should throw when the provided Authentication Tag is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");

        await expect(
          backend.decrypt(
            ciphertext,
            contentEncryptionKey,
            additionalAuthenticatedData,
            initializationVector,
            badAuthenticationTag,
          ),
        ).rejects.toThrow(error);
      });

      it("should decrypt the provided Ciphertext.", async () => {
        await expect(
          backend.decrypt(
            ciphertext,
            contentEncryptionKey,
            additionalAuthenticatedData,
            initializationVector,
            authenticationTag,
          ),
        ).resolves.toStrictEqual(plaintext);
      });
    });

    describe("generateInitializationVector()", () => {
      it("should generate an Initialization Vector.", async () => {
        await expect(backend.generateInitializationVector()).resolves.toStrictEqual(initializationVector);
      });
    });
  });

  describe("A256CBC-HS512", () => {
    const backend = new AESCBCContentEncryptionBackend("A256CBC-HS512");

    const ciphertext = Buffer.from("beF1okLtAlp5RJDN84sAb7ubLkBxreRJzYQ5HHpQlbY", "base64url");
    const contentEncryptionKey = Buffer.from(
      "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-Pw",
      "base64url",
    );

    const authenticationTag = Buffer.from("QKqpbDyl9dMstNhWZpqARnJRSKTvTZfvSfADUYAIDQo", "base64url");

    const badLengthContentEncryptionKey = Buffer.from("wLARG5KC1qensboTOzTtzUBOlyBcofxtPjBhrwIAwgc", "base64url");
    const badContentEncryptionKey = Buffer.from(
      "3W4hyOL4jOd-oprrMP6ekbjAafnWP86PLumqNFYmPUkMoWg7Tvimoy2gW-7sjOL7AjBllfjoboMCIDtmLVxZ9w",
      "base64url",
    );

    const badAuthenticationTag = Buffer.from("2HyIWq7GmrUSM4NuE1UkWfW-2xZ424a7NNib8TZdKxQ", "base64url");

    describe("encrypt()", () => {
      it("should throw when the length of the provided Content Encryption Key is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided Content Encryption Key is invalid.");

        await expect(
          backend.encrypt(plaintext, badLengthContentEncryptionKey, additionalAuthenticatedData, initializationVector),
        ).rejects.toThrow(error);
      });

      it("should throw when the length of the provided Initialization Vector is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided Initialization Vector is invalid.");

        await expect(
          backend.encrypt(plaintext, contentEncryptionKey, additionalAuthenticatedData, badLengthInitializationVector),
        ).rejects.toThrow(error);
      });

      it("should encrypt the provided Plaintext.", async () => {
        await expect(
          backend.encrypt(plaintext, contentEncryptionKey, additionalAuthenticatedData, initializationVector),
        ).resolves.toStrictEqual([ciphertext, authenticationTag]);
      });
    });

    describe("decrypt()", () => {
      it("should throw when the length of the provided Content Encryption Key is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided Content Encryption Key is invalid.");

        await expect(
          backend.decrypt(
            ciphertext,
            badLengthContentEncryptionKey,
            additionalAuthenticatedData,
            initializationVector,
            authenticationTag,
          ),
        ).rejects.toThrow(error);
      });

      it("should throw when the length of the provided Initialization Vector is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided Initialization Vector is invalid.");

        await expect(
          backend.decrypt(
            ciphertext,
            contentEncryptionKey,
            additionalAuthenticatedData,
            badLengthInitializationVector,
            authenticationTag,
          ),
        ).rejects.toThrow(error);
      });

      it("should throw when the provided Ciphertext is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");

        await expect(
          backend.decrypt(
            badCiphertext,
            contentEncryptionKey,
            additionalAuthenticatedData,
            initializationVector,
            authenticationTag,
          ),
        ).rejects.toThrow(error);
      });

      it("should throw when the provided Content Encryption Key is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");

        await expect(
          backend.decrypt(
            ciphertext,
            badContentEncryptionKey,
            additionalAuthenticatedData,
            initializationVector,
            authenticationTag,
          ),
        ).rejects.toThrow(error);
      });

      it("should throw when the provided Additional Authenticated Data is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");

        await expect(
          backend.decrypt(
            ciphertext,
            contentEncryptionKey,
            badAdditionalAuthenticatedData,
            initializationVector,
            authenticationTag,
          ),
        ).rejects.toThrow(error);
      });

      it("should throw when the provided Initialization Vector is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");

        await expect(
          backend.decrypt(
            ciphertext,
            contentEncryptionKey,
            additionalAuthenticatedData,
            badInitializationVector,
            authenticationTag,
          ),
        ).rejects.toThrow(error);
      });

      it("should throw when the provided Authentication Tag is invalid.", async () => {
        const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");

        await expect(
          backend.decrypt(
            ciphertext,
            contentEncryptionKey,
            additionalAuthenticatedData,
            initializationVector,
            badAuthenticationTag,
          ),
        ).rejects.toThrow(error);
      });

      it("should decrypt the provided Ciphertext.", async () => {
        await expect(
          backend.decrypt(
            ciphertext,
            contentEncryptionKey,
            additionalAuthenticatedData,
            initializationVector,
            authenticationTag,
          ),
        ).resolves.toStrictEqual(plaintext);
      });
    });

    describe("generateInitializationVector()", () => {
      it("should generate an Initialization Vector.", async () => {
        await expect(backend.generateInitializationVector()).resolves.toStrictEqual(initializationVector);
      });
    });
  });
});
