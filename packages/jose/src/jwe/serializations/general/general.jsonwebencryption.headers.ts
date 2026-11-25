import type { JsonWebEncryptionHeaderParameters } from "../../header/jsonwebencryption.header.parameters.ts";

/**
 * General JSON Web Encryption Headers Recipient.
 */
export interface GeneralJsonWebEncryptionHeadersRecipient {
  /**
   * JSON Web Encryption Recipient Unprotected Header.
   */
  readonly recipientUnprotectedHeader?: Partial<JsonWebEncryptionHeaderParameters>;
}

/**
 * General JSON Web Encryption Headers.
 */
export interface GeneralJsonWebEncryptionHeaders {
  /**
   * JSON Web Encryption Protected Header.
   */
  readonly protectedHeader?: Partial<JsonWebEncryptionHeaderParameters>;

  /**
   * JSON Web Encryption Unprotected Header.
   */
  readonly unprotectedHeader?: Partial<JsonWebEncryptionHeaderParameters>;

  /**
   * JSON Web Encryption Recipients.
   */
  readonly recipients: GeneralJsonWebEncryptionHeadersRecipient[];
}
