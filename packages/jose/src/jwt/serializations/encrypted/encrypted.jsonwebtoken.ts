import type { JsonWebEncryptionHeader } from "../../../jwe/header/jsonwebencryption.header.ts";
import type { JsonWebTokenClaims } from "../../claims/jsonwebtoken.claims.ts";

/**
 * Encrypted JSON Web Token.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7519.html|RFC 7519 JSON Web Token (JWT)}
 */
export interface EncryptedJsonWebToken<T extends JsonWebTokenClaims = JsonWebTokenClaims> {
  /**
   * JSON Web Token Encryption Header.
   */
  readonly header: JsonWebEncryptionHeader;

  /**
   * JSON Web Token Claims.
   */
  readonly claims: T;
}
