import { InvalidJsonWebTokenError } from "../../../../errors/invalid-jsonwebtoken.error.ts";
import type { JsonWebEncryptionHeaderParameters } from "../../../../jwe/header/jsonwebencryption.header.parameters.ts";
import { jwe } from "../../../../jwe/index.ts";
import { claims as jwtClaims } from "../../../claims/index.ts";
import type { JsonWebTokenClaimsParameters } from "../../../claims/jsonwebtoken.claims.parameters.ts";
import type { SerializeOptions } from "./serialize.options.ts";

/**
 * Serializes the provided JSON Web Token Parameters into an Encrypted Token.
 *
 * @param claimsParameters JSON Web Token Claims.
 * @param protectedHeaderParameters JSON Web Encryption Protected Header Parameters.
 * @param options Encrypted JSON Web Token serialize options.
 * @returns Encrypted JSON Web Token.
 * @throws {InvalidJoseHeaderError} The provided JSON Web Encryption Protected Header Parameters is invalid.
 * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to serialize the Encrypted JSON Web Token.
 * @throws {InvalidJsonWebTokenClaimsError} The provied JSON Web Token Claims Parameters is invalid.
 * @throws {InvalidJsonWebTokenError} Failed to serialize the Encrypted JSON Web Token.
 * @throws {TypeError} One of the provided arguments is invalid.
 */
export async function serialize(
  claimsParameters: JsonWebTokenClaimsParameters,
  protectedHeaderParameters: JsonWebEncryptionHeaderParameters,
  options?: SerializeOptions,
): Promise<string> {
  const claims = await jwtClaims.create(claimsParameters);

  try {
    return await jwe.compact.serialize(claims.toBuffer(), protectedHeaderParameters, options);
  } catch (error: unknown) {
    throw new InvalidJsonWebTokenError("Failed to serialize the Encrypted JSON Web Token.", { cause: error });
  }
}
