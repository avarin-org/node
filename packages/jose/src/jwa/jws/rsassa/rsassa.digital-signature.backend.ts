import type { Buffer } from "node:buffer";
import { constants, sign, verify } from "node:crypto";
import { promisify } from "node:util";

import { InvalidJsonWebKeyError } from "../../../errors/invalid-jsonwebkey.error.ts";
import { InvalidJsonWebSignatureError } from "../../../errors/invalid-jsonwebsignature.error.ts";
import { JsonWebKey } from "../../../jwk/jsonwebkey.ts";
import type { RsaJsonWebKeyParameters } from "../../jwk/rsa/rsa.jsonwebkey.parameters.ts";
import type { DigitalSignatureAlgorithm } from "../digital-signature-algorithm.type.ts";
import { DigitalSignatureBackend } from "../digital-signature.backend.ts";

const signAsync = promisify(sign);
const verifyAsync = promisify(verify);

/**
 * Implementation of the RSASSA Digital Signature Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3.3|RFC 7518 Digital Signature with RSASSA-PKCS1-v1_5}
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3.5|RFC 7518 Digital Signature with RSASSA-PSS}
 */
export class RSASSADigitalSignatureBackend extends DigitalSignatureBackend {
  /**
   * Hash Algorithm.
   */
  private readonly hash: string;

  /**
   * RSA Padding.
   */
  private readonly padding: number;

  /**
   * Instantiates a new RSASSA Digital Signature Backend.
   *
   * @param algorithm Digital Signature Algorithm.
   */
  public constructor(
    algorithm: Extract<DigitalSignatureAlgorithm, "PS256" | "PS384" | "PS512" | "RS256" | "RS384" | "RS512">,
  ) {
    super(algorithm);

    const bitSize = Number.parseInt(algorithm.substring(2), 10);

    this.hash = `sha-${bitSize}`;
    this.padding = algorithm.startsWith("P") ? constants.RSA_PKCS1_PSS_PADDING : constants.RSA_PKCS1_PADDING;
  }

  /**
   * Signs a Message using the provided JSON Web Key.
   *
   * @param message Message to be signed.
   * @param jsonWebKey JSON Web Key used to sign the Message.
   * @returns Signature of the Message.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used by the Digital Signature Algorithm.
   */
  public async sign(message: Buffer, jsonWebKey: JsonWebKey<RsaJsonWebKeyParameters>): Promise<Buffer> {
    this.validateJsonWebKey(jsonWebKey);

    if (jsonWebKey.cryptoKey.type !== "private") {
      throw new InvalidJsonWebKeyError("The provided JSON Web Key cannot be used to sign a Message.");
    }

    return await signAsync(this.hash, message, { key: jsonWebKey.cryptoKey, padding: this.padding });
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
    jsonWebKey: JsonWebKey<RsaJsonWebKeyParameters>,
  ): Promise<void> {
    this.validateJsonWebKey(jsonWebKey);

    const result = await verifyAsync(
      this.hash,
      message,
      { key: jsonWebKey.cryptoKey, padding: this.padding },
      signature,
    );

    if (!result) {
      throw new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
    }
  }

  /**
   * Checks if the provided JSON Web Key can be used.
   *
   * @param jsonWebKey JSON Web Key to be checked.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used by the Digital Signature Algorithm.
   */
  private validateJsonWebKey(jsonWebKey: JsonWebKey<RsaJsonWebKeyParameters>): void {
    if (
      !(jsonWebKey instanceof JsonWebKey) ||
      ("alg" in jsonWebKey.parameters && jsonWebKey.parameters.alg !== this.name)
    ) {
      throw new InvalidJsonWebKeyError("The provided JSON Web Key cannot be used by the Digital Signature Algorithm.");
    }

    if (jsonWebKey.parameters.kty !== "RSA") {
      throw new InvalidJsonWebKeyError('The Digital Signature Algorithm only accepts "RSA" JSON Web Keys.');
    }
  }
}
