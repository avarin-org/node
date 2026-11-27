import type { Buffer } from "node:buffer";

import type { JsonWebSignatureHeaderParameters } from "../../header/jsonwebsignature.header.parameters.ts";

/**
 * Compact JSON Web Signature Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-7.1|RFC 7515 JWS Compact Serialization}
 */
export interface CompactJsonWebSignatureParameters {
  /**
   * JSON Web Signature Protected Header.
   */
  readonly joseHeader: JsonWebSignatureHeaderParameters;

  /**
   * JSON Web Signature Payload.
   */
  readonly payload: Buffer | null;

  /**
   * JSON Web Signature Signature.
   */
  readonly signature: Buffer;
}
