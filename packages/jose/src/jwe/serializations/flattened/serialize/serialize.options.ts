import type { Buffer } from "node:buffer";

import type { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";

/**
 * Flattened JSON Web Encryption serialize options.
 */
export interface SerializeOptions {
  /**
   * JSON Web Encryption Additional Authenticated Data.
   */
  readonly additionalAuthenticatedData?: Buffer;

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
