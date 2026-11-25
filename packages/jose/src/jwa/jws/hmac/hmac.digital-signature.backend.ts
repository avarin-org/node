import { Buffer } from "node:buffer";
import { createHmac, timingSafeEqual } from "node:crypto";

import { InvalidJsonWebKeyError } from "../../../errors/invalid-jsonwebkey.error.ts";
import { InvalidJsonWebSignatureError } from "../../../errors/invalid-jsonwebsignature.error.ts";
import { JsonWebKey } from "../../../jwk/jsonwebkey.ts";
import type { OctetSequenceJsonWebKeyParameters } from "../../jwk/oct/octet-sequence.jsonwebkey.parameters.ts";
import type { DigitalSignatureAlgorithm } from "../digital-signature-algorithm.type.ts";
import { DigitalSignatureBackend } from "../digital-signature.backend.ts";

/**
 * Implementation of the HMAC Digital Signature Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3.2|RFC 7518 HMAC with SHA-2 Functions}
 */
export class HMACDigitalSignatureBackend extends DigitalSignatureBackend {
  /**
   * Hash Algorithm.
   */
  private readonly hash: string;

  /**
   * Size of the Secret in bytes.
   */
  private readonly keySize: number;

  /**
   * Instantiates a new HMAC Digital Signature Backend.
   *
   * @param algorithm Digital Signature Algorithm.
   */
  public constructor(algorithm: Extract<DigitalSignatureAlgorithm, "HS256" | "HS384" | "HS512">) {
    super(algorithm);

    const bitSize = Number.parseInt(algorithm.substring(2), 10);

    this.hash = `sha-${bitSize}`;
    this.keySize = bitSize >> 3;
  }

  /**
   * Signs a Message using the provided JSON Web Key.
   *
   * @param message Message to be signed.
   * @param jsonWebKey JSON Web Key used to sign the Message.
   * @returns Signature of the Message.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used by the Digital Signature Algorithm.
   */
  public async sign(message: Buffer, jsonWebKey: JsonWebKey<OctetSequenceJsonWebKeyParameters>): Promise<Buffer> {
    this.validateJsonWebKey(jsonWebKey);
    return createHmac(this.hash, jsonWebKey.cryptoKey).update(message).digest();
  }

  /**
   * Checks if the provided Signature and Message match based on the provided JSON Web Key.
   *
   * @param signature Signature to be verified.
   * @param message Message to be matched against the Signature.
   * @param jsonWebKey JSON Web Key used to verify the Signature.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used by the Digital Signature Algorithm.
   * @throws {InvalidJsonWebSignatureError} Failed to verify the provided JSON Web Signature.
   */
  public async verify(
    signature: Buffer,
    message: Buffer,
    jsonWebKey: JsonWebKey<OctetSequenceJsonWebKeyParameters>,
  ): Promise<void> {
    this.validateJsonWebKey(jsonWebKey);

    const expectedSignature = await this.sign(message, jsonWebKey);

    if (signature.byteLength !== expectedSignature.byteLength || !timingSafeEqual(signature, expectedSignature)) {
      throw new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
    }
  }

  /**
   * Checks if the provided JSON Web Key can be used.
   *
   * @param jsonWebKey JSON Web Key to be checked.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used by the Digital Signature Algorithm.
   */
  private validateJsonWebKey(jsonWebKey: JsonWebKey<OctetSequenceJsonWebKeyParameters>): void {
    if (
      !(jsonWebKey instanceof JsonWebKey) ||
      ("alg" in jsonWebKey.parameters && jsonWebKey.parameters.alg !== this.name)
    ) {
      throw new InvalidJsonWebKeyError("The provided JSON Web Key cannot be used by the Digital Signature Algorithm.");
    }

    if (jsonWebKey.parameters.kty !== "oct") {
      throw new InvalidJsonWebKeyError('The Digital Signature Algorithm only accepts "oct" JSON Web Keys.');
    }

    if (Buffer.byteLength(jsonWebKey.parameters.k, "base64url") < this.keySize) {
      throw new InvalidJsonWebKeyError(`The JSON Web Key Parameter "k" must be at least ${this.keySize} bytes.`);
    }
  }
}
