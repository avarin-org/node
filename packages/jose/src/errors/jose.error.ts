/**
 * Implementation of the Base JOSE Error.
 */
export abstract class JoseError extends Error {
  /**
   * Error Name.
   */
  public override readonly name: string = "JoseError";

  /**
   * Instantiates a new JOSE Error.
   *
   * @param message Error Message.
   * @param options Error Options
   */
  public constructor(message: string, options?: ErrorOptions) {
    super(message, options);
  }
}
