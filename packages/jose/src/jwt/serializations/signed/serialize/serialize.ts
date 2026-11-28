import { InvalidJsonWebTokenError } from "../../../../errors/invalid-jsonwebtoken.error.ts";
import type { JsonWebSignatureHeaderParameters } from "../../../../jws/header/jsonwebsignature.header.parameters.ts";
import { jws } from "../../../../jws/index.ts";
import { claims as jwtClaims } from "../../../claims/index.ts";
import type { JsonWebTokenClaimsParameters } from "../../../claims/jsonwebtoken.claims.parameters.ts";
import type { SerializeOptions } from "./serialize.options.ts";

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
export async function serialize(
  claimsParameters: JsonWebTokenClaimsParameters,
  protectedHeaderParameters: JsonWebSignatureHeaderParameters,
  options?: SerializeOptions,
): Promise<string> {
  const claims = await jwtClaims.create(claimsParameters);

  try {
    return await jws.compact.serialize(claims.toBuffer(), protectedHeaderParameters, options);
  } catch (error: unknown) {
    throw new InvalidJsonWebTokenError("Failed to serialize the Signed JSON Web Token.", { cause: error });
  }
}
