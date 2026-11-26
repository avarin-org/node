import { Functions } from "@avarin/primitives/functions";
import { Objects } from "@avarin/primitives/objects";
import type { Constructor } from "@avarin/primitives/types";

import { InvalidJsonWebTokenClaimsError } from "../../../errors/invalid-jsonwebtoken-claims.error.ts";
import { JsonWebTokenClaims } from "../jsonwebtoken.claims.js";
import type { JsonWebTokenClaimsParameters } from "../jsonwebtoken.claims.parameters.ts";

/**
 * Creates a JSON Web Token Claims based on the provided JSON Web Token Claims Parameters.
 *
 * @param parameters JSON Web Token Claims Parameters.
 * @param additionalParameters Optional additional JSON Web Token Claims Parameters.
 * @returns JSON Web Token Claims.
 * @throws {InvalidJsonWebTokenClaimsError} The provided JSON Web Token Claims Parameters is invalid.
 */
export async function create(
  parameters: JsonWebTokenClaimsParameters,
  additionalParameters?: Partial<JsonWebTokenClaimsParameters>,
): Promise<JsonWebTokenClaims>;

/**
 * Creates a JSON Web Token Claims based on the provided JSON Web Token Claims Parameters.
 *
 * @param ClaimsConstructor JSON Web Token Claims Constructor.
 * @param parameters JSON Web Token Claims Parameters.
 * @param additionalParameters Optional additional JSON Web Token Claims Parameters.
 * @returns JSON Web Token Claims.
 * @throws {InvalidJsonWebTokenClaimsError} The provided JSON Web Token Claims Parameters is invalid.
 */
export async function create<T extends JsonWebTokenClaims>(
  ClaimsConstructor: Constructor<T>,
  parameters: JsonWebTokenClaimsParameters,
  additionalParameters?: Partial<JsonWebTokenClaimsParameters>,
): Promise<T>;

/**
 * Creates a JSON Web Token Claims based on the provided JSON Web Token Claims Parameters.
 *
 * @param parametersOrClaimsConstructor JSON Web Token Claims Parameters or JSON Web Token Claims Constructor.
 * @param parametersOrAdditionalParameters JSON Web Token Claims Parameters or Optional additional JSON Web Token Claims
 *   Parameters.
 * @param additionalParameters Optional additional JSON Web Token Claims Parameters.
 * @returns JSON Web Token Claims.
 * @throws {InvalidJsonWebTokenClaimsError} The provided JSON Web Token Claims Parameters is invalid.
 */
export async function create<T extends JsonWebTokenClaims = JsonWebTokenClaims>(
  parametersOrClaimsConstructor: JsonWebTokenClaimsParameters | Constructor<T>,
  parametersOrAdditionalParameters?: JsonWebTokenClaimsParameters | Partial<JsonWebTokenClaimsParameters>,
  additionalParameters?: Partial<JsonWebTokenClaimsParameters>,
): Promise<T> {
  const ClaimsConstructor = Functions.isClass(parametersOrClaimsConstructor)
    ? parametersOrClaimsConstructor
    : JsonWebTokenClaims;

  const parameters = Functions.isClass(parametersOrClaimsConstructor)
    ? parametersOrAdditionalParameters!
    : parametersOrClaimsConstructor;

  if (arguments.length === 2 && !Functions.isClass(parametersOrClaimsConstructor)) {
    additionalParameters = parametersOrAdditionalParameters;
  }

  if (ClaimsConstructor !== JsonWebTokenClaims && !(ClaimsConstructor.prototype instanceof JsonWebTokenClaims)) {
    throw new TypeError("The provided JSON Web Token Claims Constructor is invalid.");
  }

  if (!Objects.isPlain(parameters)) {
    throw new InvalidJsonWebTokenClaimsError("The provided JSON Web Token Claims Parameters is invalid.");
  }

  if (!Objects.isPlain(additionalParameters)) {
    throw new InvalidJsonWebTokenClaimsError("The provided JSON Web Token Claims Parameters is invalid.");
  }

  const jsonWebTokenClaimsParameters: JsonWebTokenClaimsParameters = { ...parameters, ...additionalParameters };

  return new ClaimsConstructor(jsonWebTokenClaimsParameters) as T;
}
