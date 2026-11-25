import { Buffer } from "node:buffer";
import { createHash, diffieHellman, randomBytes } from "node:crypto";
import { promisify } from "node:util";

import { Strings } from "@avarin/primitives/strings";

import { InvalidJoseHeaderError } from "../../../../errors/invalid-jose-header.error.ts";
import { InvalidJsonWebKeyError } from "../../../../errors/invalid-jsonwebkey.error.ts";
import type { JsonWebEncryptionHeader } from "../../../../jwe/header/jsonwebencryption.header.ts";
import { jwk } from "../../../../jwk/index.ts";
import type { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import type { EllipticCurveJsonWebKeyParameters } from "../../../jwk/ec/elliptic-curve.jsonwebkey.parameters.ts";
import type { OctetSequenceJsonWebKeyParameters } from "../../../jwk/oct/octet-sequence.jsonwebkey.parameters.ts";
import { AESKWKeyManagementBackend } from "../aeskw/aeskw.key-management.backend.js";
import type { KeyManagementAlgorithm } from "../key-management-algorithm.type.ts";
import { KeyManagementBackend } from "../key-management.backend.ts";
import type { ECDHESJsonWebEncryptionHeaderParameters } from "./ecdhes.jsonwebencryption.header.parameters.ts";

const randomBytesAsync = promisify(randomBytes);

/**
 * Implementation of the ECDH-ES Key Management Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6|RFC 7518 Key Agreement with Elliptic Curve Diffie-Hellman Ephemeral Static}
 */
export class ECDHESKeyManagementBackend extends KeyManagementBackend {
  /**
   * AES Key Wrap Key Management Backend.
   */
  private readonly aesKeyWrapBackend: AESKWKeyManagementBackend | null = null;

  /**
   * Instantiates a new ECDH-ES Key Management Backend.
   *
   * @param name Key Management Algorithm.
   */
  public constructor(
    name: Extract<KeyManagementAlgorithm, "ECDH-ES" | "ECDH-ES+A128KW" | "ECDH-ES+A192KW" | "ECDH-ES+A256KW">,
  ) {
    super(name);

    if (name !== "ECDH-ES") {
      this.aesKeyWrapBackend = new AESKWKeyManagementBackend(
        name.substring(8) as ConstructorParameters<typeof AESKWKeyManagementBackend>[0],
      );
    }
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
    jsonWebKey: JsonWebKey<EllipticCurveJsonWebKeyParameters>,
    header: JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>,
  ): Promise<Buffer> {
    this.validateJsonWebKey(jsonWebKey);
    await this.validateJoseHeaderParameters(header.parameters);

    switch (this.name) {
      case "ECDH-ES": {
        return Buffer.alloc(0);
      }

      default: {
        const sharedSecret = await this.deriveKey(jsonWebKey, header);

        const aesKeyWrapJsonWebKey = await jwk.create<OctetSequenceJsonWebKeyParameters>({
          k: sharedSecret.toString("base64url"),
          kty: "oct",
        });

        return await this.aesKeyWrapBackend!.wrap(contentEncryptionKey, aesKeyWrapJsonWebKey, header);
      }
    }
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
    jsonWebKey: JsonWebKey<EllipticCurveJsonWebKeyParameters>,
    header: JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>,
  ): Promise<Buffer> {
    this.validateJsonWebKey(jsonWebKey);
    await this.validateJoseHeaderParameters(header.parameters);

    const sharedSecret = await this.deriveKey(jsonWebKey, header);

    switch (this.name) {
      case "ECDH-ES": {
        return sharedSecret;
      }

      default: {
        const aesKeyWrapJsonWebKey = await jwk.create<OctetSequenceJsonWebKeyParameters>({
          k: sharedSecret.toString("base64url"),
          kty: "oct",
        });

        return await this.aesKeyWrapBackend!.unwrap(encryptedKey, aesKeyWrapJsonWebKey, header);
      }
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
    jsonWebKey: JsonWebKey<EllipticCurveJsonWebKeyParameters>,
    header: JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>,
  ): Promise<Buffer> {
    this.validateJsonWebKey(jsonWebKey);
    await this.validateJoseHeaderParameters(header.parameters);

    switch (this.name) {
      case "ECDH-ES": {
        return await this.deriveKey(jsonWebKey, header);
      }

      default: {
        return await randomBytesAsync(header.contentEncryptionBackend.contentEncryptionKeySize);
      }
    }
  }

  /**
   * Checks if the provided JSON Web Key can be used.
   *
   * @param jsonWebKey JSON Web Key to be checked.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used by the Key Management Algorithm.
   */
  protected override validateJsonWebKey(jsonWebKey: JsonWebKey<EllipticCurveJsonWebKeyParameters>): void {
    super.validateJsonWebKey(jsonWebKey);

    if (jsonWebKey.parameters.kty !== "EC") {
      throw new InvalidJsonWebKeyError('The Key Management Algorithm only accepts "EC" JSON Web Keys.');
    }
  }

  /**
   * Validates the provided JOSE Header Parameters.
   *
   * @param parameters JOSE Header Parameters.
   * @throws {InvalidJoseHeaderError} The provided JOSE Header Parameters is invalid.
   */
  private async validateJoseHeaderParameters(parameters: ECDHESJsonWebEncryptionHeaderParameters): Promise<void> {
    if (!jwk.check(parameters.epk) || "d" in parameters.epk) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "epk".');
    }

    try {
      const ephemeralKey = await jwk.create(parameters.epk);
      this.validateJsonWebKey(ephemeralKey);
    } catch (error: unknown) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "epk".', { cause: error });
    }

    if ("apu" in parameters && !Strings.isNonEmpty(parameters.apu)) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "apu".');
    }

    if ("apv" in parameters && !Strings.isNonEmpty(parameters.apv)) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "apv".');
    }

    if ("apu" in parameters && "apv" in parameters && parameters.apu === parameters.apv) {
      throw new InvalidJoseHeaderError('The JOSE Header Parameters "apu" and "apv" cannot be equal.');
    }
  }

  /**
   * Checks if both JSON Web Keys can be used to generate a shared secret.
   *
   * @param jsonWebKey JSON Web Key of the recipient.
   * @param ephemeralKey JSON Web Key of the producer.
   * @throws {InvalidJoseHeaderError} The provided JSON Web Encryption Header Parameters is invalid.
   */
  private validateJsonWebKeys(
    jsonWebKey: JsonWebKey<EllipticCurveJsonWebKeyParameters>,
    ephemeralKey: JsonWebKey<EllipticCurveJsonWebKeyParameters>,
  ): void {
    if (jsonWebKey.parameters.crv !== ephemeralKey.parameters.crv) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "epk".');
    }
  }

  /**
   * Performs a Diffie-Hellman to obtain a Shared Secret and derives a Key using Concat KDF.
   *
   * @param jsonWebKey Recipient JSON Web key.
   * @param header JSON Web Encryption Header Parameters.
   * @returns Derived Key.
   */
  private async deriveKey(
    jsonWebKey: JsonWebKey<EllipticCurveJsonWebKeyParameters>,
    header: JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>,
  ): Promise<Buffer> {
    const ephemeralKey = await jwk.create(header.parameters.epk);
    this.validateJsonWebKeys(jsonWebKey, ephemeralKey);
    const sharedSecret = diffieHellman({ privateKey: jsonWebKey.cryptoKey, publicKey: ephemeralKey.cryptoKey });

    const keyLength =
      this.name === "ECDH-ES"
        ? header.contentEncryptionBackend.contentEncryptionKeySize << 3
        : Number.parseInt(this.name.substring(9, 12), 10);

    const keyLengthBuffer = Buffer.alloc(4);
    keyLengthBuffer.writeUInt32BE(keyLength);

    const partyUInfo = header.parameters.apu;
    const partyVInfo = header.parameters.apv;

    const value = Buffer.concat([
      this.lengthAndInput(Buffer.from(this.name === "ECDH-ES" ? header.parameters.enc : this.name, "ascii")),
      this.lengthAndInput(Strings.isNonEmpty(partyUInfo) ? Buffer.from(partyUInfo, "base64url") : Buffer.alloc(0)),
      this.lengthAndInput(Strings.isNonEmpty(partyVInfo) ? Buffer.from(partyVInfo, "base64url") : Buffer.alloc(0)),
      keyLengthBuffer,
      Buffer.alloc(0),
    ]);

    return this.concatKdf(sharedSecret, keyLength, value);
  }

  /**
   * Returns a Buffer containing a 32-bit long length of the provided input followed by the input itself.
   *
   * @param input Input value to be formatted.
   * @returns Resulting LV Buffer.
   */
  private lengthAndInput(input: Buffer): Buffer {
    const length = Buffer.alloc(4);
    length.writeUInt32BE(input.length);
    return Buffer.concat([length, input]);
  }

  /**
   * Returns the result of the Concat KDF.
   *
   * @param secret Diffie-Hellman Shared Secret.
   * @param keyLength Key length.
   * @param value Input value.
   * @returns Resulting Concat KDF.
   */
  private concatKdf(secret: Buffer, keyLength: number, value: Buffer): Buffer {
    const iterations = Math.ceil((keyLength >> 3) / 32);
    const kdf = Buffer.alloc(iterations << 5);

    for (let iteration = 0; iteration < iterations; iteration += 1) {
      const input = Buffer.alloc(4 + secret.length + value.length);

      input.writeUInt32BE(iteration + 1);
      input.set(secret, 4);
      input.set(value, 4 + secret.length);

      kdf.set(createHash("sha-256").update(input).digest(), iteration << 5);
    }

    return kdf.subarray(0, keyLength >> 3);
  }
}
