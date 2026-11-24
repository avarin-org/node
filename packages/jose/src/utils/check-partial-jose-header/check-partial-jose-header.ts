import type { JoseHeaderParameters } from "../../jose/jose-header.parameters.ts";
import { JoseHeader } from "../../jose/jose-header.ts";

/**
 * Checks if the provided data is a valid JOSE Header Parameters object.
 *
 * @param parameters JOSE Header Parameters.
 * @returns Whether or not the provided data is a valid JOSE Header Parameters object.
 */
export function checkPartialJoseHeader(parameters: unknown): parameters is JoseHeaderParameters {
  try {
    Reflect.construct(JoseHeader, [parameters]);
    return true;
  } catch {
    return false;
  }
}
