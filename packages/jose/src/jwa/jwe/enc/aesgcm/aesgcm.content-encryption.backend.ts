import { Buffer } from "node:buffer";
import { createCipheriv, createDecipheriv } from "node:crypto";
import type { CipherGCMTypes } from "node:crypto";

import { InvalidJsonWebEncryptionError } from "../../../../errors/invalid-jsonwebencryption.error.ts";
import type { ContentEncryptionAlgorithm } from "../content-encryption-algorithm.type.ts";
import { ContentEncryptionBackend } from "../content-encryption.backend.ts";

/**
 * Implementation of the AES GCM Content Encryption Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-5.3|RFC 7518 Content Encryption with AES GCM}
 */
export class AESGCMContentEncryptionBackend extends ContentEncryptionBackend {
  /**
   * Cipher Algorithm.
   */
  private readonly cipher: CipherGCMTypes;

  /**
   * Instantiates a new AES GCM Content Encryption Backend.
   *
   * @param algorithm Content Encryption Algorithm.
   */
  public constructor(algorithm: Extract<ContentEncryptionAlgorithm, "A128GCM" | "A192GCM" | "A256GCM">) {
    const cekSize = Number.parseInt(algorithm.substring(1, 4), 10);

    super(algorithm, cekSize >> 3, 12);

    this.cipher = `aes-${cekSize}-gcm` as CipherGCMTypes;
  }

  /**
   * Encrypts the provided Plaintext and Additional Authenticated Data.
   *
   * @param plaintext Plaintext to be encrypted.
   * @param contentEncryptionKey Content Encryption Key.
   * @param additionalAuthenticatedData Additional Authenticated Data.
   * @param initializationVector Initialization Vector.
   * @returns Ciphertext and Authentication Tag.
   * @throws {InvalidJsonWebEncryptionError} Failed to encrypt the provided Plaintext.
   */
  public async encrypt(
    plaintext: Buffer,
    contentEncryptionKey: Buffer,
    additionalAuthenticatedData: Buffer,
    initializationVector: Buffer,
  ): Promise<[Buffer, Buffer]> {
    this.validateContentEncryptionKey(contentEncryptionKey);
    this.validateInitializationVector(initializationVector);

    const cipher = createCipheriv(this.cipher, contentEncryptionKey, initializationVector, { authTagLength: 16 });
    cipher.setAAD(additionalAuthenticatedData);

    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authenticationTag = cipher.getAuthTag();

    return [ciphertext, authenticationTag];
  }

  /**
   * Decrypts the provided Ciphertext.
   *
   * @param ciphertext Ciphertext to be decrypted.
   * @param contentEncryptionKey Content Encryption Key.
   * @param additionalAuthenticatedData Additional Authenticated Data.
   * @param initializationVector Initialization Vector.
   * @param authenticationTag Authentication Tag.
   * @returns Plaintext.
   * @throws {InvalidJsonWebEncryptionError} Failed to decrypt the provided Ciphertext.
   */
  public async decrypt(
    ciphertext: Buffer,
    contentEncryptionKey: Buffer,
    additionalAuthenticatedData: Buffer,
    initializationVector: Buffer,
    authenticationTag: Buffer,
  ): Promise<Buffer> {
    this.validateContentEncryptionKey(contentEncryptionKey);
    this.validateInitializationVector(initializationVector);

    const decipher = createDecipheriv(this.cipher, contentEncryptionKey, initializationVector, { authTagLength: 16 });

    decipher.setAAD(additionalAuthenticatedData);
    decipher.setAuthTag(authenticationTag);

    try {
      return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } catch (error: unknown) {
      throw new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.", { cause: error });
    }
  }
}
