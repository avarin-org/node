import type { JsonWebSignatureHeaderParameters } from "../../header/jsonwebsignature.header.parameters.ts";

/**
 * Flattened JSON Web Signature Headers.
 */
export interface FlattenedJsonWebSignatureHeaders {
  /**
   * JSON Web Signature Protected Header.
   */
  readonly protectedHeader?: Partial<JsonWebSignatureHeaderParameters>;

  /**
   * JSON Web Signature Unprotected Header.
   */
  readonly unprotectedHeader?: Partial<JsonWebSignatureHeaderParameters>;
}
