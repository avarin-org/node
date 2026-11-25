import { JoseError } from "./jose.error.ts";

/**
 * Raised when the provided JSON Web Encryption or JSON Web Encryption Parameters is invalid.
 */
export class InvalidJsonWebEncryptionError extends JoseError {
  /**
   * Error Name.
   */
  public override readonly name: string = "InvalidJsonWebEncryptionError";

  /**
   * Instantiates a new Invalid JSON Web Encryption Error.
   *
   * @param message Error Message.
   * @param options Error Options
   */
  public constructor(message: string, options?: ErrorOptions) {
    super(message, options);
  }
}
