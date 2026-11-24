import type { Buffer } from "node:buffer";

import type { JsonWebSignatureHeaderParameters } from "../../header/jsonwebsignature.header.parameters.ts";
import type { JsonWebSignatureHeader } from "../../header/jsonwebsignature.header.ts";

/**
 * General JSON Web Signature Parameters Signature.
 */
export interface GeneralJsonWebSignatureParametersSignature {
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
  readonly header: JsonWebSignatureHeader;

  /**
   * JSON Web Signature Signature.
   */
  readonly signature: Buffer;
}

/**
 * General JSON Web Signature Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-7.2.1|RFC 7515 General JWS JSON Serialization Syntax}
 */
export interface GeneralJsonWebSignatureParameters {
  /**
   * JSON Web Signature Payload.
   */
  readonly payload: Buffer | null;

  /**
   * JSON Web Signature Signatures.
   */
  readonly signatures: GeneralJsonWebSignatureParametersSignature[];
}
