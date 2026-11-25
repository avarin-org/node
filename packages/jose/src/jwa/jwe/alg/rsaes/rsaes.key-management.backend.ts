import type { Buffer } from "node:buffer";
import { constants, privateDecrypt, publicEncrypt, randomBytes } from "node:crypto";
import { promisify } from "node:util";

import { InvalidJsonWebEncryptionError } from "../../../../errors/invalid-jsonwebencryption.error.ts";
import { InvalidJsonWebKeyError } from "../../../../errors/invalid-jsonwebkey.error.ts";
import type { JsonWebEncryptionHeader } from "../../../../jwe/header/jsonwebencryption.header.ts";
import type { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import type { RsaJsonWebKeyParameters } from "../../../jwk/rsa/rsa.jsonwebkey.parameters.ts";
import type { KeyManagementAlgorithm } from "../key-management-algorithm.type.ts";
import { KeyManagementBackend } from "../key-management.backend.ts";

const randomBytesAsync = promisify(randomBytes);

/**
 * Implementation of the RSAES Key Management Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-4.2|RFC 7518 Key Encryption with RSAES-PKCS1-v1_5}
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-4.3|RFC 7518 Key Encryption with RSAES OAEP}
 */
export class RSAESKeyManagementBackend extends KeyManagementBackend {
  /**
   * Hash Algorithm.
   */
  private readonly hash?: string;

  /**
   * RSA Padding.
   */
  private readonly padding: number;

  /**
   * Instantiates a new RSAES Key Wrap Key Management Backend.
   *
   * @param name Key Management Algorithm.
   */
  public constructor(
    name: Extract<KeyManagementAlgorithm, "RSA-OAEP" | "RSA-OAEP-256" | "RSA-OAEP-384" | "RSA-OAEP-512" | "RSA1_5">,
  ) {
    super(name);

    if (name !== "RSA1_5") {
      this.hash = name === "RSA-OAEP" ? "sha-1" : `sha-${name.substring(9)}`;
    }

    this.padding = name === "RSA1_5" ? constants.RSA_PKCS1_PADDING : constants.RSA_PKCS1_OAEP_PADDING;
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
    jsonWebKey: JsonWebKey<RsaJsonWebKeyParameters>,
    _header: JsonWebEncryptionHeader,
  ): Promise<Buffer> {
    this.validateJsonWebKey(jsonWebKey);

    return publicEncrypt(
      { key: jsonWebKey.cryptoKey, oaepHash: this.hash, padding: this.padding },
      contentEncryptionKey,
    );
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
    jsonWebKey: JsonWebKey<RsaJsonWebKeyParameters>,
    _header: JsonWebEncryptionHeader,
  ): Promise<Buffer> {
    this.validateJsonWebKey(jsonWebKey);

    if (jsonWebKey.cryptoKey.type !== "private") {
      throw new InvalidJsonWebKeyError("The provided JSON Web Key cannot be used to unwrap an Encrypted Key.");
    }

    try {
      return privateDecrypt({ key: jsonWebKey.cryptoKey, oaepHash: this.hash, padding: this.padding }, encryptedKey);
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
    jsonWebKey: JsonWebKey<RsaJsonWebKeyParameters>,
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
  protected override validateJsonWebKey(jsonWebKey: JsonWebKey<RsaJsonWebKeyParameters>): void {
    super.validateJsonWebKey(jsonWebKey);

    if (jsonWebKey.parameters.kty !== "RSA") {
      throw new InvalidJsonWebKeyError('The Key Management Algorithm only accepts "RSA" JSON Web Keys.');
    }
  }
}
