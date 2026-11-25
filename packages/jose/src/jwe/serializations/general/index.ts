import { decode } from "./decode/decode.ts";
import { deserialize } from "./deserialize/deserialize.ts";
import { serialize } from "./serialize/serialize.ts";

interface GeneralJsonWebEncryptionMethods {
  /**
   * Decodes the provided General JSON Web Encryption Token into its Parameters.
   *
   * @param token General JSON Web Encryption Token.
   * @returns General JSON Web Encryption Parameters.
   * @throws {InvalidJsonWebEncryptionError} The provided JSON Web Encryption is invalid.
   */
  readonly decode: typeof decode;

  /**
   * Deserializes the provided General JSON Web Encryption Token.
   *
   * @param token General JSON Web Encryption Token.
   * @param options General JSON Web Encryption deserialize options.
   * @returns General JSON Web Encryption.
   * @throws {InvalidJsonWebEncryptionError} Failed to deserialize the General JSON Web Encryption.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to deserialize the General JSON Web
   *   Signature Token.
   * @throws {TypeError} One of the provided arguments is invalid.
   */
  readonly deserialize: typeof deserialize;

  /**
   * Serializes the provided JSON Web Encryption Parameters into a General Token.
   *
   * @param plaintext JSON Web Encryption Plaintext.
   * @param headers JSON Web Encryption Headers Parameters.
   * @param options General JSON Web Encryption serialize options.
   * @returns General JSON Web Encryption Token.
   * @throws {InvalidJoseHeaderError} One of the provided JSON Web Encryption Header Parameters is invalid.
   * @throws {InvalidJsonWebEncryptionError} Failed to serialize the General JSON Web Encryption.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to serialize the General JSON Web
   *   Encryption.
   * @throws {TypeError} One of the provided arguments is invalid.
   */
  readonly serialize: typeof serialize;
}

export const general: GeneralJsonWebEncryptionMethods = {
  decode,
  deserialize,
  serialize,
};
