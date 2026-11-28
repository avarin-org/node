import type { KeyManagementAlgorithm } from "../../../../jwa/jwe/alg/key-management-algorithm.type.ts";
import type { ContentEncryptionAlgorithm } from "../../../../jwa/jwe/enc/content-encryption-algorithm.type.ts";
import type { CompressionAlgorithm } from "../../../../jwa/jwe/zip/compression-algorithm.type.ts";
import type { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import type { JsonWebTokenClaimsOptions } from "../../../claims/jsonwebtoken.claims.options.ts";

/**
 * Encrypted JSON Web Token deserialize options.
 */
export interface DeserializeOptions {
  /**
   * JSON Web Key.
   */
  readonly jsonWebKey?: JsonWebKey;

  /**
   * Expected JSON Web Encryption Key Management Algorithms.
   */
  readonly expectedKeyManagementAlgorithms?: KeyManagementAlgorithm[];

  /**
   * Expected JSON Web Encryption Content Encryption Algorithms.
   */
  readonly expectedContentEncryptionAlgorithms?: ContentEncryptionAlgorithm[];

  /**
   * Expected JSON Web Encryption Compression Algorithms.
   */
  readonly expectedCompressionAlgorithms?: CompressionAlgorithm[];

  /**
   * JSON Web Token Claims Options.
   */
  readonly claimsOptions?: JsonWebTokenClaimsOptions;
}
