import { decode } from "./decode/decode.ts";
import { deserialize } from "./deserialize/deserialize.ts";
import { serialize } from "./serialize/serialize.ts";

interface CompactJsonWebEncryptionMethods {
  /**
   * Decodes the provided Compact JSON Web Encryption Token into its Parameters.
   *
   * @param token Compact JSON Web Encryption Token.
   * @returns Compact JSON Web Encryption Parameters.
   * @throws {InvalidJsonWebEncryptionError} The provided JSON Web Encryption is invalid.
   */
  readonly decode: typeof decode;

  /**
   * Deserializes the provided Compact JSON Web Encryption Token.
   *
   * @param token Compact JSON Web Encryption Token.
   * @param options Compact JSON Web Encryption deserialize options.
   * @returns Compact JSON Web Encryption.
   * @throws {InvalidJoseHeaderError} The JSON Web Encryption Header of the provided Compact JSON Web Encryption Token
   *   is invalid.
   * @throws {InvalidJsonWebEncryptionError} Failed to deserialize the Compact JSON Web Encryption.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to deserialize the Compact JSON Web
   *   Encryption Token.
   * @throws {TypeError} One of the provided arguments is invalid.
   */
  readonly deserialize: typeof deserialize;

  /**
   * Serializes the provided JSON Web Encryption Parameters into a Compact Token.
   *
   * @param plaintext JSON Web Encryption Plaintext.
   * @param protectedHeaderParameters JSON Web Encryption Protected Header Parameters.
   * @param options Compact JSON Web Encryption serialize options.
   * @returns Compact JSON Web Encryption Token.
   * @throws {InvalidJoseHeaderError} The provided JSON Web Encryption Protected Header Parameters is invalid.
   * @throws {InvalidJsonWebEncryptionError} Failed to serialize the Compact JSON Web Encryption.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to serialize the Compact JSON Web
   *   Encryption.
   * @throws {TypeError} One of the provided arguments is invalid.
   */
  readonly serialize: typeof serialize;
}

export const compact: CompactJsonWebEncryptionMethods = {
  decode,
  deserialize,
  serialize,
};
