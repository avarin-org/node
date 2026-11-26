import { claims } from "./claims/index.js";

interface JsonWebTokenMethods {
  /**
   * JSON Web Token Claims Methods.
   */
  readonly claims: typeof claims;
}

export const jwt: JsonWebTokenMethods = {
  claims,
};

// #region JSON Web Token Claims
export type {
  JsonWebTokenClaimValidationOptions,
  JsonWebTokenClaimsOptions,
} from "./claims/jsonwebtoken.claims.options.ts";
export type { JsonWebTokenClaimsParameters } from "./claims/jsonwebtoken.claims.parameters.ts";
export { JsonWebTokenClaims } from "./claims/jsonwebtoken.claims.ts";
// #endregion
