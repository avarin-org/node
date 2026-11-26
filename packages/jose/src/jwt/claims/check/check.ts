import { Functions } from "@avarin/primitives/functions";
import type { Constructor } from "@avarin/primitives/types";

import { JsonWebTokenClaims } from "../jsonwebtoken.claims.js";

/**
 * Checks if the provided data is a valid JSON Web Token Claims Parameters object.
 *
 * @param parameters JSON Web Token Claims Parameters.
 * @returns Whether or not the provided data is a valid JSON Web Token Claims Parameters object.
 */
export function check<T extends JsonWebTokenClaims = JsonWebTokenClaims>(
  parameters: unknown,
): parameters is T["parameters"];

/**
 * Checks if the provided data is a valid JSON Web Token Claims Parameters object.
 *
 * @param ClaimsConstructor JSON Web Token Claims Constructor.
 * @param parameters JSON Web Token Claims Parameters.
 * @returns Whether or not the provided data is a valid JSON Web Token Claims Parameters object.
 */
export function check<T extends JsonWebTokenClaims = JsonWebTokenClaims>(
  ClaimsConstructor: Constructor<T>,
  parameters: unknown,
): parameters is T["parameters"];

/**
 * Checks if the provided data is a valid JSON Web Token Claims Parameters object.
 *
 * @param parametersOrClaimsConstructor JSON Web Token Claims Parameters or JSON Web Token Claims Constructor.
 * @param parameters JSON Web Token Claims Parameters.
 * @returns Whether or not the provided data is a valid JSON Web Token Claims Parameters object.
 */
export function check<T extends JsonWebTokenClaims = JsonWebTokenClaims>(
  parametersOrClaimsConstructor: unknown,
  parameters?: unknown,
): parameters is T["parameters"] {
  const ClaimsConstructor = Functions.isClass<T>(parametersOrClaimsConstructor)
    ? parametersOrClaimsConstructor
    : JsonWebTokenClaims;

  parameters =
    arguments.length === 1 && !Functions.isClass(parametersOrClaimsConstructor)
      ? parametersOrClaimsConstructor
      : parameters;

  try {
    if (ClaimsConstructor !== JsonWebTokenClaims && !(ClaimsConstructor.prototype instanceof JsonWebTokenClaims)) {
      return false;
    }

    Reflect.construct(ClaimsConstructor, [parameters]);

    return true;
  } catch {
    return false;
  }
}
