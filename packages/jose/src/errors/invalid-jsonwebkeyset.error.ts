import { JoseError } from "./jose.error.ts";

/**
 * Raised when the provided JSON Web Key Set or JSON Web Key Set Parameters is invalid.
 */
export class InvalidJsonWebKeySetError extends JoseError {
  /**
   * Error Name.
   */
  public override readonly name: string = "InvalidJsonWebKeySetError";

  /**
   * Instantiates a new Invalid JSON Web Key Set Error.
   *
   * @param message Error Message.
   * @param options Error Options
   */
  public constructor(message: string, options?: ErrorOptions) {
    super(message, options);
  }
}
