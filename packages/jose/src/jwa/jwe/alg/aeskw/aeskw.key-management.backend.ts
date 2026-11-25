import { Buffer } from "node:buffer";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { promisify } from "node:util";

import { InvalidJsonWebEncryptionError } from "../../../../errors/invalid-jsonwebencryption.error.ts";
import { InvalidJsonWebKeyError } from "../../../../errors/invalid-jsonwebkey.error.ts";
import type { JsonWebEncryptionHeader } from "../../../../jwe/header/jsonwebencryption.header.ts";
import type { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import type { OctetSequenceJsonWebKeyParameters } from "../../../jwk/oct/octet-sequence.jsonwebkey.parameters.ts";
import type { KeyManagementAlgorithm } from "../key-management-algorithm.type.ts";
import { KeyManagementBackend } from "../key-management.backend.ts";

const randomBytesAsync = promisify(randomBytes);

/**
 * Implementation of the AES Key Wrap Key Management Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-4.4|RFC 7518 Key Wrapping with AES Key Wrap}
 */
export class AESKWKeyManagementBackend extends KeyManagementBackend {
  /**
   * Size of the JSON Web Key in bytes.
   */
  private readonly keySize: number;

  /**
   * Cipher Algorithm.
   */
  private readonly cipher: string;

  /**
   * Initialization Vector.
   */
  private readonly initializationVector: Buffer = Buffer.alloc(8, 0xa6);

  /**
   * Instantiates a new AES Key Wrap Key Management Backend.
   *
   * @param algorithm Key Management Algorithm.
   */
  public constructor(algorithm: Extract<KeyManagementAlgorithm, "A128KW" | "A192KW" | "A256KW">) {
    super(algorithm);

    const bitSize = Number.parseInt(algorithm.substring(1, 4), 10);

    this.keySize = bitSize >> 3;
    this.cipher = `aes${bitSize}-wrap`;
  }

  /**
   * Wraps the provided Content Encryption Key.
   *
   * @param contentEncryptionKey Content Encryption Key.
   * @param jsonWebKey JSON Web Key used to wrap the Content Encryption Key.
   * @param _header ~JSON Web Encryption Header.~
   * @returns Encrypted Key.
   * @throws {InvalidJoseHeaderError} The provided JSON Web Encryption Header Parameters is invalid.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used by the Key Management Algorithm.
   */
  public async wrap(
    contentEncryptionKey: Buffer,
    jsonWebKey: JsonWebKey<OctetSequenceJsonWebKeyParameters>,
    _header: JsonWebEncryptionHeader,
  ): Promise<Buffer> {
    this.validateJsonWebKey(jsonWebKey);
    const cipher = createCipheriv(this.cipher, jsonWebKey.cryptoKey, this.initializationVector);
    return Buffer.concat([cipher.update(contentEncryptionKey), cipher.final()]);
  }

  /**
   * Unwraps the provided Encrypted Key.
   *
   * @param encryptedKey Encrypted Key.
   * @param jsonWebKey JSON Web Key used to unwrap the Encrypted Key.
   * @param _header ~JSON Web Encryption Header.~
   * @returns Content Encryption Key.
   * @throws {InvalidJoseHeaderError} The provided JSON Web Encryption Header Parameters is invalid.
   * @throws {InvalidJsonWebEncryptionError} Failed to unwrap the provided Encrypted Key.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used by the Key Management Algorithm.
   */
  public async unwrap(
    encryptedKey: Buffer,
    jsonWebKey: JsonWebKey<OctetSequenceJsonWebKeyParameters>,
    _header: JsonWebEncryptionHeader,
  ): Promise<Buffer> {
    this.validateJsonWebKey(jsonWebKey);

    const decipher = createDecipheriv(this.cipher, jsonWebKey.cryptoKey, this.initializationVector);

    try {
      return Buffer.concat([decipher.update(encryptedKey), decipher.final()]);
    } catch (error: unknown) {
      throw new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.", { cause: error });
    }
  }

  /**
   * Generates a new Content Encryption Key.
   *
   * @param jsonWebKey JSON Web Key used to wrap the Content Encryption Key.
   * @param header JSON Web Encryption Header.
   * @returns Generated Content Encryption Key.
   * @throws {InvalidJoseHeaderError} The provided JSON Web Encryption Header Parameters is invalid.
   * @throws {InvalidJsonWebEncryptionError} Failed to generate a Content Encryption Key.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used by the Key Management Algorithm.
   */
  public async generateContentEncryptionKey(
    jsonWebKey: JsonWebKey<OctetSequenceJsonWebKeyParameters>,
    header: JsonWebEncryptionHeader,
  ): Promise<Buffer> {
    this.validateJsonWebKey(jsonWebKey);
    return await randomBytesAsync(header.contentEncryptionBackend.contentEncryptionKeySize);
  }

  /**
   * Checks if the provided JSON Web Key can be used.
   *
   * @param jsonWebKey JSON Web Key to be checked.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used by the Key Management Algorithm.
   */
  protected override validateJsonWebKey(jsonWebKey: JsonWebKey<OctetSequenceJsonWebKeyParameters>): void {
    super.validateJsonWebKey(jsonWebKey);

    if (jsonWebKey.parameters.kty !== "oct") {
      throw new InvalidJsonWebKeyError('The Key Management Algorithm only accepts "oct" JSON Web Keys.');
    }

    if (Buffer.byteLength(jsonWebKey.parameters.k, "base64url") !== this.keySize) {
      throw new InvalidJsonWebKeyError(`The JSON Web Key Parameter "k" must be ${this.keySize << 3} bits.`);
    }
  }
}
