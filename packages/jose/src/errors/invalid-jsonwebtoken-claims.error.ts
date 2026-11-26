import { JoseError } from "./jose.error.ts";

/**
 * Raised when the provided JSON Web Token Claims or JSON Web Token Claims Parameters is invalid.
 */
export class InvalidJsonWebTokenClaimsError extends JoseError {
  /**
   * Error Name.
   */
  public override readonly name: string = "InvalidJsonWebTokenClaimsError";

  /**
   * Instantiates a new Invalid JSON Web Token Claims Error.
   *
   * @param message Error Message.
   * @param options Error Options
   */
  public constructor(message: string, options?: ErrorOptions) {
    super(message, options);
  }
}
