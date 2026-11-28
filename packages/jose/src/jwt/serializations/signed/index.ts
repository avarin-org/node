import { decode } from "./decode/decode.ts";
import { deserialize } from "./deserialize/deserialize.ts";
import { serialize } from "./serialize/serialize.ts";

interface SignedJsonWebTokenMethods {
  /**
   * Decodes the provided Signed JSON Web Token into its Parameters.
   *
   * @param token Signed JSON Web Token.
   * @param options JSON Web Token Claims Options.
   * @returns Signed JSON Web Token Parameters.
   * @throws {InvalidJsonWebTokenError} The provided JSON Web Token is invalid.
   */
  readonly decode: typeof decode;

  /**
   * Deserializes the provided Signed JSON Web Token.
   *
   * @param token Signed JSON Web Token.
   * @param options Signed JSON Web Token deserialize options.
   * @returns Signed JSON Web Token.
   * @throws {InvalidJsonWebTokenError} Failed to deserialize the Signed JSON Web Token.
   */
  readonly deserialize: typeof deserialize;

  /**
   * Serializes the provided JSON Web Token Parameters into a Signed Token.
   *
   * @param claimsParameters JSON Web Token Claims.
   * @param protectedHeaderParameters JSON Web Signature Protected Header Parameters.
   * @param options Signed JSON Web Token serialize options.
   * @returns Signed JSON Web Token.
   * @throws {InvalidJoseHeaderError} The provided JSON Web Signature Protected Header Parameters is invalid.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to serialize the Signed JSON Web Token.
   * @throws {InvalidJsonWebTokenClaimsError} The provied JSON Web Token Claims Parameters is invalid.
   * @throws {InvalidJsonWebTokenError} Failed to serialize the Signed JSON Web Token.
   * @throws {TypeError} One of the provided arguments is invalid.
   */
  readonly serialize: typeof serialize;
}

export const signed: SignedJsonWebTokenMethods = {
  decode,
  deserialize,
  serialize,
};
