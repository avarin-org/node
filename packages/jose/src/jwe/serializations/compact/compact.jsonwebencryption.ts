import type { Buffer } from "node:buffer";

import type { JsonWebEncryptionHeader } from "../../header/jsonwebencryption.header.ts";

/**
 * Compact JSON Web Encryption.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-7.1|RFC 7516 JWE Compact Serialization}
 */
export interface CompactJsonWebEncryption {
  /**
   * JSON Web Encryption Plaintext.
   */
  readonly plaintext: Buffer;

  /**
   * JSON Web Encryption Protected Header.
   */
  readonly header: JsonWebEncryptionHeader;
}
