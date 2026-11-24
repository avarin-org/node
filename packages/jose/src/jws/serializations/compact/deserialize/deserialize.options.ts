import type { Buffer } from "node:buffer";

import type { DigitalSignatureAlgorithm } from "../../../../jwa/index.ts";
import type { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";

/**
 * Compact JSON Web Signature deserialize options.
 */
export interface DeserializeOptions {
  /**
   * JSON Web Key.
   */
  readonly jsonWebKey?: JsonWebKey | null;

  /**
   * Expected JSON Web Signature Digital Signature Algorithms.
   */
  readonly expectedDigitalSignatureAlgorithms?: DigitalSignatureAlgorithm[];

  /**
   * Detached Payload.
   */
  readonly detachedPayload?: Buffer;
}
