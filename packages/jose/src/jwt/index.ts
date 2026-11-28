import { claims } from "./claims/index.js";
import { encrypted } from "./serializations/encrypted/index.ts";
import { signed } from "./serializations/signed/index.ts";

interface JsonWebTokenMethods {
  /**
   * JSON Web Token Claims Methods.
   */
  readonly claims: typeof claims;

  /**
   * Encrypted JSON Web Token Methods.
   */
  readonly encrypted: typeof encrypted;

  /**
   * Signed JSON Web Token Methods.
   */
  readonly signed: typeof signed;
}

export const jwt: JsonWebTokenMethods = {
  claims,
  encrypted,
  signed,
};

// #region JSON Web Token Claims
export type {
  JsonWebTokenClaimValidationOptions,
  JsonWebTokenClaimsOptions,
} from "./claims/jsonwebtoken.claims.options.ts";
export type { JsonWebTokenClaimsParameters } from "./claims/jsonwebtoken.claims.parameters.ts";
export { JsonWebTokenClaims } from "./claims/jsonwebtoken.claims.ts";
// #endregion

// #region JSON Web Token Signed Serialization
export type { EncryptedJsonWebTokenParameters } from "./serializations/encrypted/encrypted.jsonwebtoken.parameters.ts";
export type { EncryptedJsonWebToken } from "./serializations/encrypted/encrypted.jsonwebtoken.ts";
// #endregion

// #region JSON Web Token Signed Serialization
export type { SignedJsonWebTokenParameters } from "./serializations/signed/signed.jsonwebtoken.parameters.ts";
export type { SignedJsonWebToken } from "./serializations/signed/signed.jsonwebtoken.ts";
// #endregion
