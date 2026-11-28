import { JoseError } from "./jose.error.ts";

/**
 * Raised when the provided JSON Web Token or JSON Web Token Parameters is invalid.
 */
export class InvalidJsonWebTokenError extends JoseError {
  /**
   * Error Name.
   */
  public override readonly name: string = "InvalidJsonWebTokenError";

  /**
   * Instantiates a new Invalid JSON Web Token Error.
   *
   * @param message Error Message.
   * @param options Error Options
   */
  public constructor(message: string, options?: ErrorOptions) {
    super(message, options);
  }
}
