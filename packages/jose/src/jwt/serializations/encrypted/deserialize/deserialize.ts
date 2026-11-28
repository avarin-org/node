import { InvalidJsonWebTokenError } from "../../../../errors/invalid-jsonwebtoken.error.ts";
import { jwe } from "../../../../jwe/index.ts";
import { claims as jwtClaims } from "../../../claims/index.ts";
import type { EncryptedJsonWebToken } from "../encrypted.jsonwebtoken.ts";
import type { DeserializeOptions } from "./deserialize.options.ts";

/**
 * Deserializes the provided Encrypted JSON Web Token.
 *
 * @param token Encrypted JSON Web Token.
 * @param options Encrypted JSON Web Token deserialize options.
 * @returns Encrypted JSON Web Token.
 * @throws {InvalidJsonWebTokenError} Failed to deserialize the Encrypted JSON Web Token.
 */
export async function deserialize(token: string, options: DeserializeOptions = {}): Promise<EncryptedJsonWebToken> {
  try {
    const { header, plaintext } = await jwe.compact.deserialize(token, options);

    return {
      claims: await jwtClaims.parse(plaintext.toString("utf8")),
      header,
    };
  } catch (error: unknown) {
    throw new InvalidJsonWebTokenError("The provided JSON Web Token is invalid.", { cause: error });
  }
}
