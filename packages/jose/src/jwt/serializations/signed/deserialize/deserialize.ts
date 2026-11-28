import { InvalidJsonWebTokenError } from "../../../../errors/invalid-jsonwebtoken.error.ts";
import { jws } from "../../../../jws/index.ts";
import { claims as jwtClaims } from "../../../claims/index.ts";
import type { SignedJsonWebToken } from "../signed.jsonwebtoken.ts";
import type { DeserializeOptions } from "./deserialize.options.ts";

/**
 * Deserializes the provided Signed JSON Web Token.
 *
 * @param token Signed JSON Web Token.
 * @param options Signed JSON Web Token deserialize options.
 * @returns Signed JSON Web Token.
 * @throws {InvalidJsonWebTokenError} Failed to deserialize the Signed JSON Web Token.
 */
export async function deserialize(token: string, options: DeserializeOptions = {}): Promise<SignedJsonWebToken> {
  try {
    const { header, payload } = await jws.compact.deserialize(token, options);

    return {
      claims: await jwtClaims.parse(payload.toString("utf8")),
      header,
    };
  } catch (error: unknown) {
    throw new InvalidJsonWebTokenError("The provided JSON Web Token is invalid.", { cause: error });
  }
}
