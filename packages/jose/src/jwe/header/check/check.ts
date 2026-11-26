import { Functions } from "@avarin/primitives/functions";
import type { Constructor } from "@avarin/primitives/types";

import { JsonWebEncryptionHeader } from "../jsonwebencryption.header.ts";

/**
 * Checks if the provided data is a valid JSON Web Encryption Header Parameters object.
 *
 * @param parameters JSON Web Encryption Header Parameters.
 * @returns Whether or not the provided data is a valid JSON Web Encryption Header Parameters object.
 */
export function check<T extends JsonWebEncryptionHeader = JsonWebEncryptionHeader>(
  parameters: unknown,
): parameters is T["parameters"];

/**
 * Checks if the provided data is a valid JSON Web Encryption Header Parameters object.
 *
 * @param HeaderConstructor JSON Web Encryption Header Constructor.
 * @param parameters JSON Web Encryption Header Parameters.
 * @returns Whether or not the provided data is a valid JSON Web Encryption Header Parameters object.
 */
export function check<T extends JsonWebEncryptionHeader = JsonWebEncryptionHeader>(
  HeaderConstructor: Constructor<T>,
  parameters: unknown,
): parameters is T["parameters"];

/**
 * Checks if the provided data is a valid JSON Web Encryption Header Parameters object.
 *
 * @param parametersOrHeaderConstructor JSON Web Encryption Header Parameters or JSON Web Encryption Header Constructor.
 * @param parameters JSON Web Encryption Header Parameters.
 * @returns Whether or not the provided data is a valid JSON Web Encryption Header Parameters object.
 */
export function check<T extends JsonWebEncryptionHeader = JsonWebEncryptionHeader>(
  parametersOrHeaderConstructor: unknown,
  parameters?: unknown,
): parameters is T["parameters"] {
  const HeaderConstructor = Functions.isClass<T>(parametersOrHeaderConstructor)
    ? parametersOrHeaderConstructor
    : JsonWebEncryptionHeader;

  parameters =
    arguments.length === 1 && !Functions.isClass(parametersOrHeaderConstructor)
      ? parametersOrHeaderConstructor
      : parameters;

  try {
    if (
      HeaderConstructor !== JsonWebEncryptionHeader &&
      !(HeaderConstructor.prototype instanceof JsonWebEncryptionHeader)
    ) {
      return false;
    }

    Reflect.construct(HeaderConstructor, [parameters]);

    return true;
  } catch {
    return false;
  }
}
