import { decode } from "./decode/decode.ts";
import { deserialize } from "./deserialize/deserialize.ts";
import { serialize } from "./serialize/serialize.ts";

interface CompactJsonWebSignatureMethods {
  /**
   * Decodes the provided Compact JSON Web Signature Token into its Parameters.
   *
   * @param token Compact JSON Web Signature Token.
   * @returns Compact JSON Web Signature Parameters.
   * @throws {InvalidJsonWebSignatureError} The provided JSON Web Signature is invalid.
   */
  readonly decode: typeof decode;

  /**
   * Deserializes the provided Compact JSON Web Signature Token.
   *
   * @param token Compact JSON Web Signature Token.
   * @param options Compact JSON Web Signature deserialize options.
   * @returns Compact JSON Web Signature.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to deserialize the Compact JSON Web
   *   Signature Token.
   * @throws {InvalidJsonWebSignatureError} Failed to deserialize the Compact JSON Web Signature.
   * @throws {TypeError} One of the provided arguments is invalid.
   */
  readonly deserialize: typeof deserialize;

  /**
   * Serializes the provided JSON Web Signature Parameters into a Compact Token.
   *
   * @param payload JSON Web Signature Payload.
   * @param protectedHeaderParameters JSON Web Signature Protected Header Parameters.
   * @param options Compact JSON Web Signature serialize options.
   * @returns Compact JSON Web Signature Token.
   * @throws {InvalidJoseHeaderError} The provided JSON Web Signature Protected Header Parameters are invalid.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to serialize the Compact JSON Web
   *   Signature.
   * @throws {InvalidJsonWebSignatureError} Failed to serialize the Compact JSON Web Signature.
   * @throws {TypeError} One of the provided arguments is invalid.
   */
  readonly serialize: typeof serialize;
}

export const compact: CompactJsonWebSignatureMethods = {
  decode,
  deserialize,
  serialize,
};
