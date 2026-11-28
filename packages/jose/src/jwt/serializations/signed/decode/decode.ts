import { JSON } from "@avarin/primitives/json";
import { Strings } from "@avarin/primitives/strings";

import { InvalidJsonWebTokenError } from "../../../../errors/invalid-jsonwebtoken.error.ts";
import { jws } from "../../../../jws/index.ts";
import type { JsonWebTokenClaimsParameters } from "../../../claims/jsonwebtoken.claims.parameters.ts";
import type { SignedJsonWebTokenParameters } from "../signed.jsonwebtoken.parameters.ts";

/**
 * Decodes the provided Signed JSON Web Token into its Parameters.
 *
 * @param token Signed JSON Web Token.
 * @param options JSON Web Token Claims Options.
 * @returns Signed JSON Web Token Parameters.
 * @throws {InvalidJsonWebTokenError} The provided JSON Web Token is invalid.
 */
export function decode<T extends JsonWebTokenClaimsParameters = JsonWebTokenClaimsParameters>(
  token: string,
): SignedJsonWebTokenParameters<T> {
  if (!Strings.isNonEmpty(token)) {
    throw new InvalidJsonWebTokenError("The provided JSON Web Token is invalid.");
  }

  try {
    const { joseHeader, payload, signature } = jws.compact.decode(token);

    return {
      claims: JSON.parse<T>(payload!.toString("utf8")),
      joseHeader,
      signature,
    };
  } catch (error: unknown) {
    throw new InvalidJsonWebTokenError("The provided JSON Web Token is invalid.", { cause: error });
  }
}
