import type { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";

/**
 * Encrypted JSON Web Token serialize options.
 */
export interface SerializeOptions {
  /**
   * JSON Web Key.
   */
  readonly jsonWebKey?: JsonWebKey;
}
