import type { JsonWebSignatureHeaderParameters } from "../jsonwebsignature.header.parameters.ts";
import { JsonWebSignatureHeader } from "../jsonwebsignature.header.ts";

/**
 * Checks if the provided data is a valid JSON Web Signature Header Parameters object.
 *
 * @param parameters JSON Web Signature Header Parameters.
 * @returns Whether or not the provided data is a valid JSON Web Signature Header Parameters object.
 */
export function check<T extends JsonWebSignatureHeaderParameters = JsonWebSignatureHeaderParameters>(
  parameters: unknown,
): parameters is T {
  try {
    Reflect.construct(JsonWebSignatureHeader, [parameters]);
    return true;
  } catch {
    return false;
  }
}
