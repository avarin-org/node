import type { Buffer } from "node:buffer";

import type { JsonWebEncryptionHeaderParameters } from "../../header/jsonwebencryption.header.parameters.ts";

/**
 * General JSON Web Encryption Parameters Recipient.
 */
export interface GeneralJsonWebEncryptionParametersRecipient {
  /**
   * JSON Web Encryption Header.
   */
  readonly joseHeader: JsonWebEncryptionHeaderParameters;

  /**
   * JSON Web Encryption Recipient Unprotected Header.
   */
  readonly recipientUnprotectedHeader: Partial<JsonWebEncryptionHeaderParameters> | null;

  /**
   * JSON Web Encryption Encrypted Key.
   */
  readonly encryptedKey: Buffer;
}

/**
 * General JSON Web Encryption Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-7.2.1|RFC 7516 General JWE JSON Serialization Syntax}
 */
export interface GeneralJsonWebEncryptionParameters {
  /**
   * JSON Web Encryption Protected Header.
   */
  readonly protectedHeader: Partial<JsonWebEncryptionHeaderParameters> | null;

  /**
   * JSON Web Encryption Unprotected Header.
   */
  readonly unprotectedHeader: Partial<JsonWebEncryptionHeaderParameters> | null;

  /**
   * JSON Web Encryption Initialization Vector.
   */
  readonly initializationVector: Buffer;

  /**
   * JSON Web Encryption Additional Authenticated Data.
   */
  readonly additionalAuthenticatedData: Buffer | null;

  /**
   * JSON Web Encryption Ciphertext.
   */
  readonly ciphertext: Buffer | null;

  /**
   * JSON Web Encryption Authentication Tag.
   */
  readonly authenticationTag: Buffer;

  /**
   * JSON Web Encryption Recipients.
   */
  readonly recipients: GeneralJsonWebEncryptionParametersRecipient[];
}
