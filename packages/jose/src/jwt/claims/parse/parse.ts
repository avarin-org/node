import { Functions } from "@avarin/primitives/functions";
import { JSON } from "@avarin/primitives/json";
import type { Constructor } from "@avarin/primitives/types";

import { InvalidJsonWebTokenClaimsError } from "../../../errors/invalid-jsonwebtoken-claims.error.js";
import { create } from "../create/create.ts";
import { JsonWebTokenClaims } from "../jsonwebtoken.claims.js";
import type { JsonWebTokenClaimsParameters } from "../jsonwebtoken.claims.parameters.ts";

/**
 * Parses the provided stringified JSON Web Token Claims Parameters into a JSON Web Token Claims.
 *
 * @param data Stringified JSON Web Token Claims Parameters.
 * @param additionalParameters Optional additional JSON Web Token Claims Parameters.
 * @returns JSON Web Token Claims.
 * @throws {InvalidJsonWebTokenClaimsError} The provided JSON Web Token Claims Parameters is invalid.
 */
export async function parse(
  data: string,
  additionalParameters?: Partial<JsonWebTokenClaimsParameters>,
): Promise<JsonWebTokenClaims>;

/**
 * Parses the provided stringified JSON Web Token Claims Parameters into a JSON Web Token Claims.
 *
 * @param ClaimsConstructor JSON Web Token Claims Constructor.
 * @param data Stringified JSON Web Token Claims Parameters.
 * @param additionalParameters Optional additional JSON Web Token Claims Parameters.
 * @returns JSON Web Token Claims.
 * @throws {InvalidJsonWebTokenClaimsError} The provided JSON Web Token Claims Parameters is invalid.
 */
export async function parse<T extends JsonWebTokenClaims>(
  ClaimsConstructor: Constructor<T>,
  data: string,
  additionalParameters?: Partial<JsonWebTokenClaimsParameters>,
): Promise<T>;

/**
 * Parses the provided stringified JSON Web Token Claims Parameters into a JSON Web Token Claims.
 *
 * @param dataOrClaimsConstructor Stringified JSON Web Token Claims Parameters. or JSON Web Token Claims Constructor.
 * @param dataOrAdditionalParameters Stringified JSON Web Token Claims Parameters. or Optional additional JSON Web Token
 *   Claims Parameters.
 * @param additionalParameters Optional additional JSON Web Token Claims Parameters.
 * @returns JSON Web Token Claims.
 * @throws {InvalidJsonWebTokenClaimsError} The provided JSON Web Token Claims Parameters is invalid.
 */
export async function parse<T extends JsonWebTokenClaims = JsonWebTokenClaims>(
  dataOrClaimsConstructor: string | Constructor<T>,
  dataOrAdditionalParameters?: string | Partial<JsonWebTokenClaimsParameters>,
  additionalParameters?: Partial<JsonWebTokenClaimsParameters>,
): Promise<T> {
  const ClaimsConstructor = Functions.isClass(dataOrClaimsConstructor)
    ? dataOrClaimsConstructor
    : (JsonWebTokenClaims as Constructor<T>);

  const data = Functions.isClass(dataOrClaimsConstructor)
    ? (dataOrAdditionalParameters! as string)
    : dataOrClaimsConstructor;

  if (arguments.length === 2 && !Functions.isClass(dataOrClaimsConstructor)) {
    additionalParameters = dataOrAdditionalParameters as Partial<JsonWebTokenClaimsParameters>;
  }

  try {
    return await create<T>(ClaimsConstructor, JSON.parse(data), additionalParameters);
  } catch (error: unknown) {
    throw new InvalidJsonWebTokenClaimsError("The provided JSON Web Token Claims Parameters is invalid.", {
      cause: error,
    });
  }
}
