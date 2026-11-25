import { header } from "./header/index.ts";
import { register } from "./register/register.ts";
import { compact } from "./serializations/compact/index.ts";
import { flattened } from "./serializations/flattened/index.ts";
import { general } from "./serializations/general/index.ts";

interface JsonWebEncryptionMethods {
  /**
   * Compact JSON Web Encryption Methods.
   */
  readonly compact: typeof compact;

  /**
   * Flattened JSON Web Encryption Methods.
   */
  readonly flattened: typeof flattened;

  /**
   * General JSON Web Encryption Methods.
   */
  readonly general: typeof general;

  /**
   * JSON Web Encryption Header Methods.
   */
  readonly header: typeof header;

  /**
   * Registers the provided JSON Web Encryption Backend into the Registry.
   *
   * @param backend JSON Web Encryption Backend to be registered.
   * @throws {TypeError} The provided JSON Web Encryption Backend is invalid or is already registered.
   */
  readonly register: typeof register;
}

export const jwe: JsonWebEncryptionMethods = {
  compact,
  flattened,
  general,
  header,
  register,
};

// #region JSON Web Encryption Header
export type { JsonWebEncryptionHeaderParameters } from "./header/jsonwebencryption.header.parameters.ts";
export { JsonWebEncryptionHeader } from "./header/jsonwebencryption.header.ts";
// #endregion

// #region JSON Web Encryption Compact Serialization
export type { CompactJsonWebEncryptionParameters } from "./serializations/compact/compact.jsonwebencryption.parameters.ts";
export type { CompactJsonWebEncryptionToken } from "./serializations/compact/compact.jsonwebencryption.token.ts";
export type { CompactJsonWebEncryption } from "./serializations/compact/compact.jsonwebencryption.ts";
// #endregion

// #region JSON Web Encryption Flattened Serialization
export type { FlattenedJsonWebEncryptionHeaders } from "./serializations/flattened/flattened.jsonwebencryption.headers.ts";
export type { FlattenedJsonWebEncryptionParameters } from "./serializations/flattened/flattened.jsonwebencryption.parameters.ts";
export type { FlattenedJsonWebEncryptionToken } from "./serializations/flattened/flattened.jsonwebencryption.token.ts";
export type { FlattenedJsonWebEncryption } from "./serializations/flattened/flattened.jsonwebencryption.ts";
// #endregion

// #region JSON Web Encryption General Serialization
export type {
  GeneralJsonWebEncryptionHeaders,
  GeneralJsonWebEncryptionHeadersRecipient,
} from "./serializations/general/general.jsonwebencryption.headers.ts";
export type {
  GeneralJsonWebEncryptionParameters,
  GeneralJsonWebEncryptionParametersRecipient,
} from "./serializations/general/general.jsonwebencryption.parameters.ts";
export type {
  GeneralJsonWebEncryptionToken,
  GeneralJsonWebEncryptionTokenRecipient,
} from "./serializations/general/general.jsonwebencryption.token.ts";
export type {
  GeneralJsonWebEncryption,
  GeneralJsonWebEncryptionRecipient,
} from "./serializations/general/general.jsonwebencryption.ts";
// #endregion
