import { Buffer } from "node:buffer";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import type { CipherGCMTypes } from "node:crypto";
import { promisify } from "node:util";

import { Strings } from "@avarin/primitives/strings";

import { InvalidJoseHeaderError } from "../../../../errors/invalid-jose-header.error.ts";
import { InvalidJsonWebEncryptionError } from "../../../../errors/invalid-jsonwebencryption.error.ts";
import { InvalidJsonWebKeyError } from "../../../../errors/invalid-jsonwebkey.error.ts";
import type { JsonWebEncryptionHeader } from "../../../../jwe/header/jsonwebencryption.header.ts";
import type { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import type { OctetSequenceJsonWebKeyParameters } from "../../../jwk/oct/octet-sequence.jsonwebkey.parameters.ts";
import type { KeyManagementAlgorithm } from "../key-management-algorithm.type.ts";
import { KeyManagementBackend } from "../key-management.backend.ts";
import type { AESGCMKWJsonWebEncryptionHeaderParameters } from "./aesgcmkw.jsonwebencryption.header.parameters.ts";

const randomBytesAsync = promisify(randomBytes);

/**
 * Implementation of the AES GCM Key Wrap Key Management Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-4.7|RFC 7518 Key Encryption with AES GCM}
 */
export class AESGCMKWKeyManagementBackend extends KeyManagementBackend {
  /**
   * Size of the Wrap Key in bytes.
   */
  private readonly keySize: number;

  /**
   * Cipher Algorithm.
   */
  private readonly cipher: CipherGCMTypes;

  /**
   * Size of the Initialization Vector in bytes.
   */
  private readonly initializationVectorSize: number = 12;

  /**
   * Size of the Authentication Tag in bytes.
   */
  private readonly authenticationTagLength: number = 16;

  /**
   * Additional Authenticated Data.
   */
  private readonly additionalAuthenticatedData: Buffer = Buffer.alloc(0);

  /**
   * Instantiates a new AES GCM Key Wrap Key Management Backend.
   *
   * @param algorithm Key Management Algorithm.
   */
  public constructor(algorithm: Extract<KeyManagementAlgorithm, "A128GCMKW" | "A192GCMKW" | "A256GCMKW">) {
    super(algorithm);

    const bitSize = Number.parseInt(algorithm.substring(1, 4), 10);

    this.keySize = bitSize >> 3;
    this.cipher = `aes-${bitSize}-gcm` as CipherGCMTypes;
  }

  /**
   * Wraps the provided Content Encryption Key.
   *
   * @param contentEncryptionKey Content Encryption Key.
   * @param jsonWebKey JSON Web Key used to wrap the Content Encryption Key.
   * @param header JSON Web Encryption Header.
   * @returns Encrypted Key.
   * @throws {InvalidJoseHeaderError} The provided JSON Web Encryption Header Parameters is invalid.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used by the Key Management Algorithm.
   */
  public async wrap(
    contentEncryptionKey: Buffer,
    jsonWebKey: JsonWebKey<OctetSequenceJsonWebKeyParameters>,
    header: JsonWebEncryptionHeader,
  ): Promise<Buffer> {
    this.validateJsonWebKey(jsonWebKey);

    const initializationVector = await randomBytesAsync(this.initializationVectorSize);
    const cipher = createCipheriv(this.cipher, jsonWebKey.cryptoKey, initializationVector, {
      authTagLength: this.authenticationTagLength,
    });

    cipher.setAAD(this.additionalAuthenticatedData);

    const encryptedKey = Buffer.concat([cipher.update(contentEncryptionKey), cipher.final()]);
    const authenticationTag = cipher.getAuthTag();

    const headerParameters: Partial<AESGCMKWJsonWebEncryptionHeaderParameters> = {
      iv: initializationVector.toString("base64url"),
      tag: authenticationTag.toString("base64url"),
    };

    Object.assign(header.parameters, headerParameters);

    return encryptedKey;
  }

  /**
   * Unwraps the provided Encrypted Key.
   *
   * @param encryptedKey Encrypted Key.
   * @param jsonWebKey JSON Web Key used to unwrap the Encrypted Key.
   * @param header JSON Web Encryption Header.
   * @returns Content Encryption Key.
   * @throws {InvalidJoseHeaderError} The provided JSON Web Encryption Header Parameters is invalid.
   * @throws {InvalidJsonWebEncryptionError} Failed to unwrap the provided Encrypted Key.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used by the Key Management Algorithm.
   */
  public async unwrap(
    encryptedKey: Buffer,
    jsonWebKey: JsonWebKey<OctetSequenceJsonWebKeyParameters>,
    header: JsonWebEncryptionHeader<AESGCMKWJsonWebEncryptionHeaderParameters>,
  ): Promise<Buffer> {
    this.validateJsonWebKey(jsonWebKey);
    this.validateJoseHeaderParameters(header.parameters);

    const initializationVector = Buffer.from(header.parameters.iv, "base64url");
    const authenticationTag = Buffer.from(header.parameters.tag, "base64url");

    const decipher = createDecipheriv(this.cipher, jsonWebKey.cryptoKey, initializationVector, {
      authTagLength: this.authenticationTagLength,
    });

    decipher.setAAD(this.additionalAuthenticatedData);
    decipher.setAuthTag(authenticationTag);

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

  /**
   * Validates the provided JOSE Header Parameters.
   *
   * @param parameters JOSE Header Parameters.
   * @throws {InvalidJoseHeaderError} The provided JOSE Header Parameters is invalid.
   */
  private validateJoseHeaderParameters(parameters: AESGCMKWJsonWebEncryptionHeaderParameters): void {
    if (
      !Strings.isNonEmpty(parameters.iv) ||
      Buffer.byteLength(parameters.iv, "base64url") !== this.initializationVectorSize
    ) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "iv".');
    }

    if (
      !Strings.isNonEmpty(parameters.tag) ||
      Buffer.byteLength(parameters.tag, "base64url") !== this.authenticationTagLength
    ) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "tag".');
    }
  }
}
