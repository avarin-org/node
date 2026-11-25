import type { JsonWebEncryptionHeaderParameters } from "../../header/jsonwebencryption.header.parameters.ts";

/**
 * General JSON Web Encryption Token Recipient.
 */
export interface GeneralJsonWebEncryptionTokenRecipient {
  /**
   * JSON Web Encryption Recipient Unprotected Header.
   */
  readonly header?: Partial<JsonWebEncryptionHeaderParameters>;

  /**
   * JSON Web Encryption Encrypted Key.
   */
  readonly encrypted_key: string;
}

/**
 * General JSON Web Encryption Token.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-7.2.1|RFC 7516 General JWE JSON Serialization Syntax}
 */
export interface GeneralJsonWebEncryptionToken {
  /**
   * JSON Web Encryption Protected Header.
   */
  readonly protected?: string;

  /**
   * JSON Web Encryption Unprotected Header.
   */
  readonly unprotected?: Partial<JsonWebEncryptionHeaderParameters>;

  /**
   * JSON Web Encryption Initialization Vector.
   */
  readonly iv: string;

  /**
   * JSON Web Encryption Additional Authenticated Data.
   */
  readonly aad?: string;

  /**
   * JSON Web Encryption Payload.
   */
  readonly ciphertext?: string;

  /**
   * JSON Web Encryption Authentication Tag.
   */
  readonly tag: string;

  /**
   * JSON Web Encryption Recipients.
   */
  readonly recipients: GeneralJsonWebEncryptionTokenRecipient[];
}
