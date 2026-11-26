/**
 * Defines the Options for the Validation of a specific JSON Web Token Claim.
 */
export interface JsonWebTokenClaimValidationOptions {
  /**
   * Defines if the JSON Web Token Claim is Essential.
   *
   * An Essential JSON Web Token Claim must be provided.
   */
  readonly essential?: boolean;

  /**
   * Defines the specific value that a JSON Web Token Claim is required to have.
   */
  readonly value?: unknown;

  /**
   * Defines the Set of values that the JSON Web Token Claim can assume.
   *
   * For it to be valid, the JSON Web Token Claim must match at least one of the specified values.
   */
  readonly values?: unknown[];
}

/**
 * JSON Web Token Claims Options.
 */
export interface JsonWebTokenClaimsOptions {
  /**
   * Indicates if the value of the JSON Web Token Claim "exp" should be ignored.
   *
   * @default false
   */
  readonly ignoreExpired?: boolean;

  /**
   * Options used to validate the JSON Web Token Claims in a fine-grained manner.
   */
  readonly validationOptions?: NodeJS.Dict<JsonWebTokenClaimValidationOptions | null>;
}
