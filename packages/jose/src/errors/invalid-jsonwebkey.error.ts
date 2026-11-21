import { JoseError } from "./jose.error.ts";

/**
 * Raised when the provided JSON Web Key or JSON Web Key Parameters is invalid.
 */
export class InvalidJsonWebKeyError extends JoseError {
  /**
   * Error Name.
   */
  public override readonly name: string = "InvalidJsonWebKeyError";

  /**
   * Instantiates a new Invalid JSON Web Key Error.
   *
   * @param message Error Message.
   * @param options Error Options
   */
  public constructor(message: string, options?: ErrorOptions) {
    super(message, options);
  }
}
