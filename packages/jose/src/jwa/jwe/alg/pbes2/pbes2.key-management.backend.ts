import { Buffer } from "node:buffer";
import { pbkdf2, randomBytes } from "node:crypto";
import { promisify } from "node:util";

import { Strings } from "@avarin/primitives/strings";

import { InvalidJoseHeaderError } from "../../../../errors/invalid-jose-header.error.ts";
import { InvalidJsonWebKeyError } from "../../../../errors/invalid-jsonwebkey.error.ts";
import type { JsonWebEncryptionHeader } from "../../../../jwe/header/jsonwebencryption.header.ts";
import { jwk } from "../../../../jwk/index.ts";
import type { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import type { OctetSequenceJsonWebKeyParameters } from "../../../jwk/oct/octet-sequence.jsonwebkey.parameters.ts";
import { AESKWKeyManagementBackend } from "../aeskw/aeskw.key-management.backend.ts";
import type { KeyManagementAlgorithm } from "../key-management-algorithm.type.ts";
import { KeyManagementBackend } from "../key-management.backend.ts";
import type { PBES2JsonWebEncryptionHeaderParameters } from "./pbes2.jsonwebencryption.header.parameters.ts";

const pbkdf2Async = promisify(pbkdf2);
const randomBytesAsync = promisify(randomBytes);

/**
 * Implementation of the PBES2 Key Management Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-4.8|RFC 7518 Key Encryption with PBES2}
 */
export class PBES2KeyManagementBackend extends KeyManagementBackend {
  /**
   * Hash Algorithm.
   */
  private readonly hash: string;

  /**
   * AES Key Wrap Key Management Backend.
   */
  private readonly aesKeyWrapBackend: AESKWKeyManagementBackend;

  /**
   * Minimum size of the Salt Input in bytes.
   */
  private readonly minimumSaltSize: number = 8;

  /**
   * Minimum number of Iteration Count.
   */
  private readonly minimumIterationCount: number = 1000;

  /**
   * Instantiates a new PBES2 Key Management Backend.
   *
   * @param name Key Management Algorithm.
   */
  public constructor(
    name: Extract<KeyManagementAlgorithm, "PBES2-HS256+A128KW" | "PBES2-HS384+A192KW" | "PBES2-HS512+A256KW">,
  ) {
    super(name);

    const [hashSize, keySize] = /^PBES2-HS([0-9]{3})\+A([0-9]{3})KW$/u
      .exec(name)!
      .slice(1)
      .map((value) => Number.parseInt(value, 10)) as [number, number];

    this.hash = `sha-${hashSize}`;

    this.aesKeyWrapBackend = new AESKWKeyManagementBackend(
      `A${keySize}KW` as ConstructorParameters<typeof AESKWKeyManagementBackend>[0],
    );
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
    header: JsonWebEncryptionHeader<PBES2JsonWebEncryptionHeaderParameters>,
  ): Promise<Buffer> {
    this.validateJsonWebKey(jsonWebKey);
    this.validateJoseHeaderParameters(header.parameters);

    const derivedKey = await this.deriveKey(jsonWebKey, header);

    const aesKeyWrapJsonWebKey = await jwk.create<OctetSequenceJsonWebKeyParameters>({
      k: derivedKey.toString("base64url"),
      kty: "oct",
    });

    return await this.aesKeyWrapBackend.wrap(contentEncryptionKey, aesKeyWrapJsonWebKey, header);
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
    header: JsonWebEncryptionHeader<PBES2JsonWebEncryptionHeaderParameters>,
  ): Promise<Buffer> {
    this.validateJsonWebKey(jsonWebKey);
    this.validateJoseHeaderParameters(header.parameters);

    const derivedKey = await this.deriveKey(jsonWebKey, header);

    const aesKeyWrapJsonWebKey = await jwk.create<OctetSequenceJsonWebKeyParameters>({
      k: derivedKey.toString("base64url"),
      kty: "oct",
    });

    return await this.aesKeyWrapBackend.unwrap(encryptedKey, aesKeyWrapJsonWebKey, header);
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
    header: JsonWebEncryptionHeader<PBES2JsonWebEncryptionHeaderParameters>,
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
  }

  /**
   * Validates the provided JOSE Header Parameters.
   *
   * @param parameters JOSE Header Parameters.
   * @throws {InvalidJoseHeaderError} The provided JOSE Header Parameters is invalid.
   */
  private validateJoseHeaderParameters(parameters: PBES2JsonWebEncryptionHeaderParameters): void {
    if (!Strings.isNonEmpty(parameters.p2s) || Buffer.byteLength(parameters.p2s, "base64url") < this.minimumSaltSize) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "p2s".');
    }

    if (
      typeof parameters.p2c !== "number" ||
      !Number.isSafeInteger(parameters.p2c) ||
      parameters.p2c < this.minimumIterationCount
    ) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "p2c".');
    }
  }

  /**
   * Performs a PBKDF2 to derive a Key.
   *
   * @param jsonWebKey Recipient JSON Web key.
   * @param header JSON Web Encryption Header Parameters.
   * @returns Derived Key.
   */
  private async deriveKey(
    jsonWebKey: JsonWebKey<OctetSequenceJsonWebKeyParameters>,
    header: JsonWebEncryptionHeader<PBES2JsonWebEncryptionHeaderParameters>,
  ): Promise<Buffer> {
    const keySize = Number.parseInt(this.aesKeyWrapBackend.name.substring(1, 4), 10) >> 3;

    const salt = Buffer.concat([
      Buffer.from(this.name, "utf8"),
      Buffer.from([0x00]),
      Buffer.from(header.parameters.p2s, "base64url"),
    ]);

    const password = Buffer.from(jsonWebKey.parameters.k, "base64url");

    return await pbkdf2Async(password, salt, header.parameters.p2c, keySize, this.hash);
  }
}
