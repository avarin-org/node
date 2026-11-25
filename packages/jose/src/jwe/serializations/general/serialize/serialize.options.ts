import type { Buffer } from "node:buffer";

import type { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";

/**
 * General JSON Web Encryption serialize options.
 */
export interface SerializeOptions {
  /**
   * JSON Web Encryption Additional Authenticated Data.
   */
  readonly additionalAuthenticatedData?: Buffer;

  /**
   * JSON Web Keys.
   */
  readonly jsonWebKeys?: JsonWebKey[];

  /**
   * Detached Ciphertext.
   *
   * @default false
   */
  readonly detached?: boolean;
}
