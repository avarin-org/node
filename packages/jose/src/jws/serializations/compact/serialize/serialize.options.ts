import type { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";

/**
 * Compact JSON Web Signature serialize options.
 */
export interface SerializeOptions {
  /**
   * JSON Web Key.
   */
  readonly jsonWebKey?: JsonWebKey | null;

  /**
   * Detached Payload.
   *
   * @default false
   */
  readonly detached?: boolean;
}
