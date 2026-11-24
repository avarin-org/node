import type { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";

/**
 * General JSON Web Signature serialize options.
 */
export interface SerializeOptions {
  /**
   * JSON Web Keys.
   */
  readonly jsonWebKeys?: (JsonWebKey | null)[];

  /**
   * Detached Payload.
   *
   * @default false
   */
  readonly detached?: boolean;
}
