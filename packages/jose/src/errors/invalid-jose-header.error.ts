import { JoseError } from "./jose.error.ts";

/**
 * Raised when the provided JOSE Header or JOSE Header Parameters is invalid.
 */
export class InvalidJoseHeaderError extends JoseError {
  /**
   * Error Name.
   */
  public override readonly name: string = "InvalidJoseHeaderError";

  /**
   * Instantiates a new Invalid JOSE Header Error.
   *
   * @param message Error Message.
   * @param options Error Options
   */
  public constructor(message: string, options?: ErrorOptions) {
    super(message, options);
  }
}
