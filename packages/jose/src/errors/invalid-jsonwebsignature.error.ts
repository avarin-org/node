import { JoseError } from "./jose.error.ts";

/**
 * Raised when the provided JSON Web Signature or JSON Web Signature Parameters is invalid.
 */
export class InvalidJsonWebSignatureError extends JoseError {
  /**
   * Error Name.
   */
  public override readonly name: string = "InvalidJsonWebSignatureError";

  /**
   * Instantiates a new Invalid JSON Web Signature Error.
   *
   * @param message Error Message.
   * @param options Error Options
   */
  public constructor(message: string, options?: ErrorOptions) {
    super(message, options);
  }
}
