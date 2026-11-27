import type { Buffer } from "node:buffer";

import type { JsonWebSignatureHeaderParameters } from "../../header/jsonwebsignature.header.parameters.ts";

/**
 * Flattened JSON Web Signature Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-7.2.2|RFC 7515 Flattened JWS JSON Serialization Syntax}
 */
export interface FlattenedJsonWebSignatureParameters {
  /**
   * JSON Web Signature Protected Header.
   */
  readonly protectedHeader: Partial<JsonWebSignatureHeaderParameters> | null;

  /**
   * JSON Web Signature Unprotected Header.
   */
  readonly unprotectedHeader: Partial<JsonWebSignatureHeaderParameters> | null;

  /**
   * JSON Web Signature Header.
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
