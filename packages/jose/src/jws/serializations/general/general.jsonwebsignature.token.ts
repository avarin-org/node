import type { JsonWebSignatureHeaderParameters } from "../../header/jsonwebsignature.header.parameters.ts";

/**
 * General JSON Web Signature Token Signature Parameters.
 */
export interface GeneralJsonWebSignatureTokenSignature {
  /**
   * JSON Web Signature Protected Header.
   */
  readonly protected?: string;

  /**
   * JSON Web Signature Unprotected Header.
   */
  readonly header?: Partial<JsonWebSignatureHeaderParameters>;

  /**
   * JSON Web Signature Signature.
   */
  readonly signature: string;
}

/**
 * General JSON Web Signature Token.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-7.2.1|RFC 7515 General JWS JSON Serialization Syntax}
 */
export interface GeneralJsonWebSignatureToken {
  /**
   * JSON Web Signature Payload.
   */
  readonly payload?: string;

  /**
   * JSON Web Signature Signatures.
   */
  readonly signatures: GeneralJsonWebSignatureTokenSignature[];
}
