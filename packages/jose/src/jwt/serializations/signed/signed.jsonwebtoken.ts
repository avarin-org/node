import type { JsonWebSignatureHeader } from "../../../jws/header/jsonwebsignature.header.ts";
import type { JsonWebTokenClaims } from "../../claims/jsonwebtoken.claims.ts";

/**
 * Signed JSON Web Token.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7519.html|RFC 7519 JSON Web Token (JWT)}
 */
export interface SignedJsonWebToken<T extends JsonWebTokenClaims = JsonWebTokenClaims> {
  /**
   * JSON Web Token Signature Header.
   */
  readonly header: JsonWebSignatureHeader;

  /**
   * JSON Web Token Claims.
   */
  readonly claims: T;
}
