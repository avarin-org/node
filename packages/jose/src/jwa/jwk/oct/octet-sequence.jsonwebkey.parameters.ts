import type { JsonWebKeyParameters } from "../../../jwk/jsonwebkey.parameters.ts";

/**
 * Octet Sequence JSON Web Key Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.4|RFC 7518 Parameters for Symmetric Keys}
 */
export interface OctetSequenceJsonWebKeyParameters extends JsonWebKeyParameters<"oct"> {
  /**
   * Key Value.
   *
   * Contains the value of the symmetric key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.4.1|RFC 7518 "k" (Key Value) Parameter}
   */
  readonly k: string;
}
