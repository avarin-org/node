import { decode } from "./decode/decode.ts";
import { deserialize } from "./deserialize/deserialize.ts";
import { serialize } from "./serialize/serialize.ts";

interface FlattenedJsonWebSignatureMethods {
  /**
   * Decodes the provided Flattened JSON Web Signature Token into its Parameters.
   *
   * @param token Flattened JSON Web Signature Token.
   * @returns Flattened JSON Web Signature Parameters.
   * @throws {InvalidJsonWebSignatureError} The provided JSON Web Signature is invalid.
   */
  readonly decode: typeof decode;

  /**
   * Deserializes the provided Flattened JSON Web Signature Token.
   *
   * @param token Flattened JSON Web Signature Token.
   * @param options Flattened JSON Web Signature deserialize options.
   * @returns Flattened JSON Web Signature.
   * @throws {InvalidJoseHeaderError} The JSON Web Signature Header of the provided Flattened JSON Web Signature Token
   *   is invalid.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to deserialize the Flattened JSON Web
   *   Signature Token.
   * @throws {InvalidJsonWebSignatureError} Failed to deserialize the Flattened JSON Web Signature.
   * @throws {TypeError} One of the provided arguments is invalid.
   */
  readonly deserialize: typeof deserialize;

  /**
   * Serializes the provided JSON Web Signature Parameters into a Flattened Token.
   *
   * @param payload JSON Web Signature Payload.
   * @param headers JSON Web Signature Headers Parameters.
   * @param options Flattened JSON Web Signature serialize options.
   * @returns Flattened JSON Web Signature Token.
   * @throws {InvalidJoseHeaderError} One of the provided JSON Web Signature Header Parameters is invalid.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to serialize the Flattened JSON Web
   *   Signature.
   * @throws {InvalidJsonWebSignatureError} Failed to serialize the Flattened JSON Web Signature.
   * @throws {TypeError} One of the provided arguments is invalid.
   */
  readonly serialize: typeof serialize;
}

export const flattened: FlattenedJsonWebSignatureMethods = {
  decode,
  deserialize,
  serialize,
};
