import { decode } from "./decode/decode.ts";
import { deserialize } from "./deserialize/deserialize.ts";
import { serialize } from "./serialize/serialize.ts";

interface EncryptedJsonWebTokenMethods {
  /**
   * Decodes the provided Encrypted JSON Web Token into its Parameters.
   *
   * @param token Encrypted JSON Web Token.
   * @param options JSON Web Token Claims Options.
   * @returns Encrypted JSON Web Token Parameters.
   * @throws {InvalidJsonWebTokenError} The provided JSON Web Token is invalid.
   */
  readonly decode: typeof decode;

  /**
   * Deserializes the provided Encrypted JSON Web Token.
   *
   * @param token Encrypted JSON Web Token.
   * @param options Encrypted JSON Web Token deserialize options.
   * @returns Encrypted JSON Web Token.
   * @throws {InvalidJsonWebTokenError} Failed to deserialize the Encrypted JSON Web Token.
   */
  readonly deserialize: typeof deserialize;

  /**
   * Serializes the provided JSON Web Token Parameters into an Encrypted Token.
   *
   * @param claimsParameters JSON Web Token Claims.
   * @param protectedHeaderParameters JSON Web Encryption Protected Header Parameters.
   * @param options Encrypted JSON Web Token serialize options.
   * @returns Encrypted JSON Web Token.
   * @throws {InvalidJoseHeaderError} The provided JSON Web Encryption Protected Header Parameters is invalid.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to serialize the Encrypted JSON Web
   *   Token.
   * @throws {InvalidJsonWebTokenClaimsError} The provied JSON Web Token Claims Parameters is invalid.
   * @throws {InvalidJsonWebTokenError} Failed to serialize the Encrypted JSON Web Token.
   * @throws {TypeError} One of the provided arguments is invalid.
   */
  readonly serialize: typeof serialize;
}

export const encrypted: EncryptedJsonWebTokenMethods = {
  decode,
  deserialize,
  serialize,
};
