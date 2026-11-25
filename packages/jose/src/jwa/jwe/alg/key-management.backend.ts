import type { Buffer } from "node:buffer";

import { InvalidJsonWebKeyError } from "../../../errors/invalid-jsonwebkey.error.ts";
import type { JsonWebEncryptionHeader } from "../../../jwe/header/jsonwebencryption.header.ts";
import type { JsonWebKey } from "../../../jwk/jsonwebkey.ts";
import type { KeyManagementAlgorithm } from "./key-management-algorithm.type.ts";

/**
 * Implementation of the Key Management Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-4|RFC 7518 Cryptographic Algorithms for Key Management}
 */
export abstract class KeyManagementBackend {
  /**
   * Key Management Algorithm.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.1|RFC 7516 "alg" (Algorithm) Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-4.1|RFC 7518 "alg" (Algorithm) Header Parameter Values for JWE}
   */
  public readonly name: KeyManagementAlgorithm;

  /**
   * Instantiates a new Key Management Backend.
   *
   * @param name Key Management Algorithm.
   */
  public constructor(name: KeyManagementAlgorithm) {
    this.name = name;
  }

  /**
   * Wraps the provided Content Encryption Key.
   *
   * @param contentEncryptionKey Content Encryption Key.
   * @param jsonWebKey JSON Web Key used to wrap the Content Encryption Key.
   * @param header JSON Web Encryption Header.
   * @returns Encrypted Key.
   * @throws {InvalidJoseHeaderError} The provided JSON Web Encryption Header Parameters is invalid.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used by the JSON Web Encryption Key Management
   *   Algorithm.
   */
  public abstract wrap(
    contentEncryptionKey: Buffer,
    jsonWebKey: JsonWebKey,
    header: JsonWebEncryptionHeader,
  ): Promise<Buffer>;

  /**
   * Unwraps the provided Encrypted Key.
   *
   * @param encryptedKey Encrypted Key.
   * @param jsonWebKey JSON Web Key used to unwrap the Encrypted Key.
   * @param header JSON Web Encryption Header.
   * @returns Content Encryption Key.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used by the Key Management Algorithm.
   * @throws {InvalidJoseHeaderError} The provided JSON Web Encryption Header Parameters is invalid.
   * @throws {InvalidJsonWebEncryptionError} Failed to unwrap the provided Encrypted Key.
   */
  public abstract unwrap(
    encryptedKey: Buffer,
    jsonWebKey: JsonWebKey,
    header: JsonWebEncryptionHeader,
  ): Promise<Buffer>;

  /**
   * Generates a new Content Encryption Key.
   *
   * @param jsonWebKey JSON Web Key used to wrap the Content Encryption Key.
   * @param header JSON Web Encryption Header.
   * @returns Generated Content Encryption Key.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used by the Key Management Algorithm.
   * @throws {InvalidJoseHeaderError} The provided JSON Web Encryption Header Parameters is invalid.
   * @throws {InvalidJsonWebEncryptionError} Failed to generate a Content Encryption Key.
   */
  public abstract generateContentEncryptionKey(
    jsonWebKey: JsonWebKey,
    header: JsonWebEncryptionHeader,
  ): Promise<Buffer>;

  /**
   * Checks if the provided JSON Web Key can be used.
   *
   * @param jsonWebKey JSON Web Key to be checked.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used by the Key Management Algorithm.
   */
  protected validateJsonWebKey(jsonWebKey: JsonWebKey): void {
    if ("alg" in jsonWebKey.parameters && jsonWebKey.parameters.alg !== this.name) {
      throw new InvalidJsonWebKeyError("The provided JSON Web Key cannot be used by the Key Management Algorithm.");
    }
  }
}
