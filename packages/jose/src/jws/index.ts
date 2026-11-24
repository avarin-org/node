import { header } from "./header/index.ts";
import { register } from "./register/register.ts";
import { compact } from "./serializations/compact/index.ts";
import { flattened } from "./serializations/flattened/index.ts";
import { general } from "./serializations/general/index.ts";

interface JsonWebSignatureMethods {
  /**
   * Compact JSON Web Signature Methods.
   */
  readonly compact: typeof compact;

  /**
   * Flattened JSON Web Signature Methods.
   */
  readonly flattened: typeof flattened;

  /**
   * General JSON Web Signature Methods.
   */
  readonly general: typeof general;

  /**
   * JSON Web Signature Header Methods.
   */
  readonly header: typeof header;

  /**
   * Registers the provided Digital Signature Backend into the Registry.
   *
   * @param backend Digital Signature Backend to be registered.
   * @throws {TypeError} The provided Digital Signature Backend is invalid or is already registered.
   */
  readonly register: typeof register;
}

export const jws: JsonWebSignatureMethods = {
  compact,
  flattened,
  general,
  header,
  register,
};

// #region JSON Web Signature Header
export type { JsonWebSignatureHeaderParameters } from "./header/jsonwebsignature.header.parameters.ts";
export { JsonWebSignatureHeader } from "./header/jsonwebsignature.header.ts";
// #endregion

// #region JSON Web Signature Compact Serialization
export type { CompactJsonWebSignatureParameters } from "./serializations/compact/compact.jsonwebsignature.parameters.ts";
export type { CompactJsonWebSignatureToken } from "./serializations/compact/compact.jsonwebsignature.token.ts";
export type { CompactJsonWebSignature } from "./serializations/compact/compact.jsonwebsignature.ts";
// #endregion

// #region JSON Web Signature Flattened Serialization
export type { FlattenedJsonWebSignatureHeaders } from "./serializations/flattened/flattened.jsonwebsignature.headers.ts";
export type { FlattenedJsonWebSignatureParameters } from "./serializations/flattened/flattened.jsonwebsignature.parameters.ts";
export type { FlattenedJsonWebSignatureToken } from "./serializations/flattened/flattened.jsonwebsignature.token.ts";
export type { FlattenedJsonWebSignature } from "./serializations/flattened/flattened.jsonwebsignature.ts";
// #endregion

// #region JSON Web Signature General Serialization
export type { GeneralJsonWebSignatureHeaders } from "./serializations/general/general.jsonwebsignature.headers.ts";
export type {
  GeneralJsonWebSignatureParameters,
  GeneralJsonWebSignatureParametersSignature,
} from "./serializations/general/general.jsonwebsignature.parameters.ts";
export type {
  GeneralJsonWebSignatureToken,
  GeneralJsonWebSignatureTokenSignature,
} from "./serializations/general/general.jsonwebsignature.token.ts";
export type {
  GeneralJsonWebSignature,
  GeneralJsonWebSignatureParsedHeaders,
} from "./serializations/general/general.jsonwebsignature.ts";
// #endregion
