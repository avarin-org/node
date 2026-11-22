import type { JsonWebKeyParameters } from "../jsonwebkey.parameters.ts";
import { JsonWebKey } from "../jsonwebkey.ts";

/**
 * Checks if the provided data is a valid JSON Web Key Parameters object.
 *
 * @param parameters JSON Web Key Parameters.
 * @returns Whether or not the provided data is a valid JSON Web Key Parameters object.
 */
export function check<T extends JsonWebKeyParameters = JsonWebKeyParameters>(parameters: unknown): parameters is T {
  try {
    Reflect.construct(JsonWebKey, [parameters]);
    return true;
  } catch {
    return false;
  }
}
