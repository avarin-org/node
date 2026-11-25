import type { JsonWebEncryptionHeaderParameters } from "../jsonwebencryption.header.parameters.ts";
import { JsonWebEncryptionHeader } from "../jsonwebencryption.header.ts";

/**
 * Checks if the provided data is a valid JSON Web Encryption Header Parameters object.
 *
 * @param parameters JSON Web Encryption Header Parameters.
 * @returns Whether or not the provided data is a valid JSON Web Encryption Header Parameters object.
 */
export function check<T extends JsonWebEncryptionHeaderParameters = JsonWebEncryptionHeaderParameters>(
  parameters: unknown,
): parameters is T {
  try {
    Reflect.construct(JsonWebEncryptionHeader, [parameters]);
    return true;
  } catch {
    return false;
  }
}
