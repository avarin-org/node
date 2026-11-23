import type { Buffer } from "node:buffer";

import type { JsonWebKey } from "../../jwk/jsonwebkey.ts";
import type { DigitalSignatureAlgorithm } from "./digital-signature-algorithm.type.ts";

/**
 * Implementation of the Digital Signature Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3|RFC 7518 Cryptographic Algorithms for Digital Signatures and MACs}
 */
export abstract class DigitalSignatureBackend {
  /**
   * Digital Signature Algorithm.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.1|RFC 7515 "alg" (Algorithm) Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1|RFC 7518 "alg" (Algorithm) Header Parameter Values for JWS}
   */
  public readonly name: DigitalSignatureAlgorithm;

  /**
   * Instantiates a new Digital Signature Backend.
   *
   * @param name Digital Signature Algorithm.
   */
  public constructor(name: DigitalSignatureAlgorithm) {
    this.name = name;
  }

  /**
   * Signs a Message using the provided JSON Web Key.
   *
   * @param message Message to be signed.
   * @param jsonWebKey JSON Web Key used to sign the Message.
   * @returns Signature of the Message.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used by the Digital Signature Algorithm.
   */
  public abstract sign(message: Buffer, jsonWebKey: JsonWebKey | null): Promise<Buffer>;

  /**
   * Checks if the provided Signature and Message match based on the provided JSON Web Key.
   *
   * @param signature Signature to be verified.
   * @param message Message to be matched against the Signature.
   * @param jsonWebKey JSON Web Key used to verify the Signature.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used by the Digital Signature Algorithm.
   * @throws {JsonWebSignatureError} Failed to verify the provided JSON Web Signature.
   */
  public abstract verify(signature: Buffer, message: Buffer, jsonWebKey: JsonWebKey | null): Promise<void>;
}
