import type { Buffer } from "node:buffer";

import type { JsonWebSignatureHeaderParameters } from "../../../jws/header/jsonwebsignature.header.parameters.ts";
import type { JsonWebTokenClaimsParameters } from "../../claims/jsonwebtoken.claims.parameters.ts";

/**
 * Signed JSON Web Token Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7519.html|RFC 7519 JSON Web Token (JWT)}
 */
export interface SignedJsonWebTokenParameters<T extends JsonWebTokenClaimsParameters = JsonWebTokenClaimsParameters> {
  /**
   * JSON Web Token Signature Header.
   */
  readonly joseHeader: JsonWebSignatureHeaderParameters;

  /**
   * JSON Web Token Claims.
   */
  readonly claims: T;

  /**
   * JSON Web Token Signature.
   */
  readonly signature: Buffer;
}
