import { Buffer } from "node:buffer";

import { InvalidJsonWebEncryptionError } from "../../../../errors/invalid-jsonwebencryption.error.ts";
import { InvalidJsonWebKeyError } from "../../../../errors/invalid-jsonwebkey.error.ts";
import type { JsonWebEncryptionHeader } from "../../../../jwe/header/jsonwebencryption.header.ts";
import type { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import type { OctetSequenceJsonWebKeyParameters } from "../../../jwk/oct/octet-sequence.jsonwebkey.parameters.ts";
import { KeyManagementBackend } from "../key-management.backend.ts";

/**
 * Implementation of the dir Key Management Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-4.5|RFC 7518 Direct Encryption with a Shared Symmetric Key}
 */
export class DirKeyManagementBackend extends KeyManagementBackend {
  /**
   * Instantiates a new dir Key Management Backend.
   */
  public constructor() {
    super("dir");
  }

  /**
   * Wraps the provided Content Encryption Key.
   *
   * @param _contentEncryptionKey ~Content Encryption Key.~
   * @param jsonWebKey JSON Web Key used to wrap the Content Encryption Key.
   * @param _header ~JSON Web Encryption Header.~
   * @returns Encrypted Key.
   * @throws {InvalidJoseHeaderError} The provided JSON Web Encryption Header Parameters is invalid.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used by the Key Management Algorithm.
   */
  public async wrap(
    _contentEncryptionKey: Buffer,
    jsonWebKey: JsonWebKey<OctetSequenceJsonWebKeyParameters>,
    _header: JsonWebEncryptionHeader,
  ): Promise<Buffer> {
    this.validateJsonWebKey(jsonWebKey);
    return Buffer.alloc(0);
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

    if (encryptedKey.byteLength !== 0) {
      throw new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
    }

    return Buffer.from(jsonWebKey.parameters.k, "base64url");
  }

  /**
   * Generates a new Content Encryption Key.
   *
   * @param jsonWebKey JSON Web Key used to wrap the Content Encryption Key.
   * @param _header ~JSON Web Encryption Header.~
   * @returns Generated Content Encryption Key.
   * @throws {InvalidJoseHeaderError} The provided JSON Web Encryption Header Parameters is invalid.
   * @throws {InvalidJsonWebEncryptionError} Failed to generate a Content Encryption Key.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used by the Key Management Algorithm.
   */
  public async generateContentEncryptionKey(
    jsonWebKey: JsonWebKey<OctetSequenceJsonWebKeyParameters>,
    _header: JsonWebEncryptionHeader,
  ): Promise<Buffer> {
    this.validateJsonWebKey(jsonWebKey);
    return Buffer.from(jsonWebKey.parameters.k, "base64url");
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
  }
}
