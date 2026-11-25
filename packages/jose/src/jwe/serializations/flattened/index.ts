import { decode } from "./decode/decode.ts";
import { deserialize } from "./deserialize/deserialize.ts";
import { serialize } from "./serialize/serialize.ts";

interface FlattenedJsonWebEncryptionMethods {
  /**
   * Decodes the provided Flattened JSON Web Encryption Token into its Parameters.
   *
   * @param token Flattened JSON Web Encryption Token.
   * @returns Flattened JSON Web Encryption Parameters.
   * @throws {InvalidJsonWebEncryptionError} The provided JSON Web Encryption is invalid.
   */
  readonly decode: typeof decode;

  /**
   * Deserializes the provided Flattened JSON Web Encryption Token.
   *
   * @param token Flattened JSON Web Encryption Token.
   * @param options Flattened JSON Web Encryption deserialize options.
   * @returns Flattened JSON Web Encryption.
   * @throws {InvalidJsonWebEncryptionError} Failed to deserialize the Flattened JSON Web Encryption.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to deserialize the Flattened JSON Web
   *   Encryption Token.
   * @throws {TypeError} One of the provided arguments is invalid.
   */
  readonly deserialize: typeof deserialize;

  /**
   * Serializes the provided JSON Web Encryption Parameters into a Flattened Token.
   *
   * @param plaintext JSON Web Encryption Plaintext.
   * @param headers JSON Web Encryption Headers Parameters.
   * @param options Flattened JSON Web Encryption serialize options.
   * @returns Flattened JSON Web Encryption Token.
   * @throws {InvalidJoseHeaderError} One of the provided JSON Web Encryption Header Parameters is invalid.
   * @throws {InvalidJsonWebEncryptionError} Failed to serialize the Flattened JSON Web Encryption.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to serialize the Flattened JSON Web
   *   Encryption.
   * @throws {TypeError} One of the provided arguments is invalid.
   */
  readonly serialize: typeof serialize;
}

export const flattened: FlattenedJsonWebEncryptionMethods = {
  decode,
  deserialize,
  serialize,
};
