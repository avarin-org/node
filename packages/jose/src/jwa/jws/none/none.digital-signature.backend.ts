import { Buffer } from "node:buffer";

import { InvalidJsonWebKeyError } from "../../../errors/invalid-jsonwebkey.error.ts";
import { InvalidJsonWebSignatureError } from "../../../errors/invalid-jsonwebsignature.error.ts";
import { DigitalSignatureBackend } from "../digital-signature.backend.ts";

/**
 * Implementation of the none Digital Signature Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3.6|RFC 7518 Using the Algorithm "none"}
 */
export class NoneDigitalSignatureBackend extends DigitalSignatureBackend {
  /**
   * Instantiates a new none Digital Signature Backend.
   */
  public constructor() {
    super("none");
  }

  /**
   * Signs a Message using the provided JSON Web Key.
   *
   * @param _message ~Message to be signed.~
   * @param jsonWebKey JSON Web Key used to sign the Message.
   * @returns Signature of the Message.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used by the Digital Signature Algorithm.
   */
  public async sign(_message: Buffer, jsonWebKey: null): Promise<Buffer> {
    this.validateJsonWebKey(jsonWebKey);
    return Buffer.alloc(0);
  }

  /**
   * Checks if the provided Signature and Message match based on the provided JSON Web Key.
   *
   * @param signature Signature to be verified.
   * @param _message ~Message to be matched against the Signature.~
   * @param jsonWebKey JSON Web Key used to verify the Signature.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used by the Digital Signature Algorithm.
   * @throws {InvalidJsonWebSignatureError} Failed to verify the provided JSON Web Signature.
   */
  public async verify(signature: Buffer, _message: Buffer, jsonWebKey: null): Promise<void> {
    this.validateJsonWebKey(jsonWebKey);

    if (signature.byteLength !== 0) {
      throw new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
    }
  }

  /**
   * Checks if the provided JSON Web Key can be used.
   *
   * @param jsonWebKey JSON Web Key to be checked.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used by the Digital Signature Algorithm.
   */
  private validateJsonWebKey(jsonWebKey: null): void {
    if (jsonWebKey !== null) {
      throw new InvalidJsonWebKeyError("The provided JSON Web Key cannot be used by the Digital Signature Algorithm.");
    }
  }
}
