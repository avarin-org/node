import type { JSON } from "@avarin/primitives/json";

import type { JsonWebKeyParameters } from "../jwk/jsonwebkey.parameters.ts";

/**
 * JSON Web Key Set Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-5|RFC 7517 JWK Set Format}
 */
export interface JsonWebKeySetParameters extends NodeJS.Dict<JSON> {
  /**
   * Array of JWK values.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-5.1|RFC 7517 "keys" Parameter}
   */
  readonly keys: JsonWebKeyParameters[];
}
