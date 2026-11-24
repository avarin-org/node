import type { Buffer } from "node:buffer";

import type { DigitalSignatureAlgorithm } from "../../../../jwa/index.ts";
import type { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";

/**
 * General JSON Web Signature deserialize options Signature.
 */
export interface DeserializeOptionsSignature {
  /**
   * JSON Web Key.
   */
  readonly jsonWebKey?: JsonWebKey | null;

  /**
   * Expected JSON Web Signature Digital Signature Algorithms.
   */
  readonly expectedDigitalSignatureAlgorithms?: DigitalSignatureAlgorithm[];
}

/**
 * General JSON Web Signature deserialize options.
 */
export interface DeserializeOptions {
  /**
   * Detached Payload.
   */
  readonly detachedPayload?: Buffer;

  /**
   * Signatures options.
   */
  readonly signatures?: DeserializeOptionsSignature[];
}
