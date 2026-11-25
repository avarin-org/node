import type { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";

/**
 * Compact JSON Web Encryption serialize options.
 */
export interface SerializeOptions {
  /**
   * JSON Web Key.
   */
  readonly jsonWebKey?: JsonWebKey;

  /**
   * Detached Ciphertext.
   *
   * @default false
   */
  readonly detached?: boolean;
}
