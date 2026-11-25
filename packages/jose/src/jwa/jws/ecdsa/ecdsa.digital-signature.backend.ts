import type { Buffer } from "node:buffer";
import { sign, verify } from "node:crypto";
import { promisify } from "node:util";

import { InvalidJsonWebKeyError } from "../../../errors/invalid-jsonwebkey.error.ts";
import { InvalidJsonWebSignatureError } from "../../../errors/invalid-jsonwebsignature.error.ts";
import { JsonWebKey } from "../../../jwk/jsonwebkey.ts";
import type { EllipticCurveJsonWebKeyParameters } from "../../jwk/ec/elliptic-curve.jsonwebkey.parameters.ts";
import type { EllipticCurve } from "../../jwk/ec/elliptic-curve.type.ts";
import type { DigitalSignatureAlgorithm } from "../digital-signature-algorithm.type.ts";
import { DigitalSignatureBackend } from "../digital-signature.backend.ts";

const signAsync = promisify(sign);
const verifyAsync = promisify(verify);

/**
 * Implementation of the ECDSA Digital Signature Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4|RFC 7518 Digital Signature with ECDSA}
 */
export class ECDSADigitalSignatureBackend extends DigitalSignatureBackend {
  /**
   * Hash Algorithm.
   */
  private readonly hash: string;

  /**
   * Elliptic Curve.
   */
  private readonly curve: EllipticCurve;

  /**
   * Mapping of the Digital Signature Algorithms to the respective Elliptic Curves.
   */
  readonly #algorithmCurveMap: Record<Extract<DigitalSignatureAlgorithm, "ES256" | "ES384" | "ES512">, EllipticCurve> =
    {
      ES256: "P-256",
      ES384: "P-384",
      ES512: "P-521",
    };

  /**
   * Instantiates a new ECDSA Digital Signature Backend.
   *
   * @param algorithm Digital Signature Algorithm.
   */
  public constructor(algorithm: Extract<DigitalSignatureAlgorithm, "ES256" | "ES384" | "ES512">) {
    super(algorithm);

    const bitSize = Number.parseInt(algorithm.substring(2, 5), 10);

    this.hash = `sha-${bitSize}`;
    this.curve = this.#algorithmCurveMap[algorithm];
  }

  /**
   * Signs a Message using the provided JSON Web Key.
   *
   * @param message Message to be signed.
   * @param jsonWebKey JSON Web Key used to sign the Message.
   * @returns Signature of the Message.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used by the Digital Signature Algorithm.
   */
  public async sign(message: Buffer, jsonWebKey: JsonWebKey<EllipticCurveJsonWebKeyParameters>): Promise<Buffer> {
    this.validateJsonWebKey(jsonWebKey);

    if (jsonWebKey.cryptoKey.type !== "private") {
      throw new InvalidJsonWebKeyError("The provided JSON Web Key cannot be used to sign a Message.");
    }

    return await signAsync(this.hash, message, { dsaEncoding: "ieee-p1363", key: jsonWebKey.cryptoKey });
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
    jsonWebKey: JsonWebKey<EllipticCurveJsonWebKeyParameters>,
  ): Promise<void> {
    this.validateJsonWebKey(jsonWebKey);

    const result = await verifyAsync(
      this.hash,
      message,
      { dsaEncoding: "ieee-p1363", key: jsonWebKey.cryptoKey },
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
  private validateJsonWebKey(jsonWebKey: JsonWebKey<EllipticCurveJsonWebKeyParameters>): void {
    if (
      !(jsonWebKey instanceof JsonWebKey) ||
      ("alg" in jsonWebKey.parameters && jsonWebKey.parameters.alg !== this.name)
    ) {
      throw new InvalidJsonWebKeyError("The provided JSON Web Key cannot be used by the Digital Signature Algorithm.");
    }

    if (jsonWebKey.parameters.kty !== "EC") {
      throw new InvalidJsonWebKeyError('The Digital Signature Algorithm only accepts "EC" JSON Web Keys.');
    }

    if (jsonWebKey.parameters.crv !== this.curve) {
      throw new InvalidJsonWebKeyError(`The JSON Web Key Parameter "crv" must be "${this.curve}".`);
    }
  }
}
