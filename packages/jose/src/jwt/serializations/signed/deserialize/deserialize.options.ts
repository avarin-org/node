import type { DigitalSignatureAlgorithm } from "../../../../jwa/jws/digital-signature-algorithm.type.ts";
import type { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import type { JsonWebTokenClaimsOptions } from "../../../claims/jsonwebtoken.claims.options.ts";

/**
 * Signed JSON Web Token deserialize options.
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
   * JSON Web Token Claims Options.
   */
  readonly claimsOptions?: JsonWebTokenClaimsOptions;
}
