import type { Buffer } from "node:buffer";

import type { JsonWebEncryptionHeaderParameters } from "../../../jwe/header/jsonwebencryption.header.parameters.ts";

/**
 * Encrypted JSON Web Token Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7519.html|RFC 7519 JSON Web Token (JWT)}
 */
export interface EncryptedJsonWebTokenParameters {
  /**
   * JSON Web Token Protected Header.
   */
  readonly joseHeader: JsonWebEncryptionHeaderParameters;

  /**
   * JSON Web Token Encrypted Key.
   */
  readonly encryptedKey: Buffer;

  /**
   * JSON Web Token Initialization Vector.
   */
  readonly initializationVector: Buffer;

  /**
   * JSON Web Token Ciphertext.
   */
  readonly ciphertext: Buffer;

  /**
   * JSON Web Token Authentication Tag.
   */
  readonly authenticationTag: Buffer;

  /**
   * JSON Web Token Additional Authenticated Data.
   */
  readonly additionalAuthenticatedData: Buffer;
}
