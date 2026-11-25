import type { Buffer } from "node:buffer";

import type { JsonWebEncryptionHeaderParameters } from "../../header/jsonwebencryption.header.parameters.ts";
import type { JsonWebEncryptionHeader } from "../../header/jsonwebencryption.header.ts";

/**
 * General JSON Web Encryption Recipient.
 */
export interface GeneralJsonWebEncryptionRecipient {
  /**
   * JSON Web Encryption Header.
   */
  readonly header: JsonWebEncryptionHeader;

  /**
   * JSON Web Encryption Recipient Unprotected Header.
   */
  readonly recipientUnprotectedHeader: Partial<JsonWebEncryptionHeaderParameters> | null;
}

/**
 * General JSON Web Encryption.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-7.2.1|RFC 7516 General JWE JSON Serialization Syntax}
 */
export interface GeneralJsonWebEncryption {
  /**
   * JSON Web Encryption Plaintext.
   */
  readonly plaintext: Buffer;

  /**
   * JSON Web Encryption Protected Header.
   */
  readonly protectedHeader: Partial<JsonWebEncryptionHeaderParameters> | null;

  /**
   * JSON Web Encryption Unprotected Header.
   */
  readonly unprotectedHeader: Partial<JsonWebEncryptionHeaderParameters> | null;

  /**
   * JSON Web Encryption Recipients.
   */
  readonly recipients: GeneralJsonWebEncryptionRecipient[];
}
