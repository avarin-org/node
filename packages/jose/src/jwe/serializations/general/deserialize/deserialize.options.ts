import type {
  CompressionAlgorithm,
  ContentEncryptionAlgorithm,
  KeyManagementAlgorithm,
} from "../../../../jwa/index.ts";
import type { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";

/**
 * General JSON Web Encryption deserialize options Recipient.
 */
export interface DeserializeOptionsRecipient {
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
}

/**
 * General JSON Web Encryption deserialize options.
 */
export interface DeserializeOptions {
  /**
   * Detached Ciphertext.
   */
  readonly detachedCiphertext?: Buffer;

  /**
   * Recipients options.
   */
  readonly recipients?: DeserializeOptionsRecipient[];
}
