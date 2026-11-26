import { Functions } from "@avarin/primitives/functions";
import type { Constructor } from "@avarin/primitives/types";

import { JsonWebSignatureHeader } from "../jsonwebsignature.header.ts";

/**
 * Checks if the provided data is a valid JSON Web Signature Header Parameters object.
 *
 * @param parameters JSON Web Signature Header Parameters.
 * @returns Whether or not the provided data is a valid JSON Web Signature Header Parameters object.
 */
export function check<T extends JsonWebSignatureHeader = JsonWebSignatureHeader>(
  parameters: unknown,
): parameters is T["parameters"];

/**
 * Checks if the provided data is a valid JSON Web Signature Header Parameters object.
 *
 * @param HeaderConstructor JSON Web Signature Header Constructor.
 * @param parameters JSON Web Signature Header Parameters.
 * @returns Whether or not the provided data is a valid JSON Web Signature Header Parameters object.
 */
export function check<T extends JsonWebSignatureHeader = JsonWebSignatureHeader>(
  HeaderConstructor: Constructor<T>,
  parameters: unknown,
): parameters is T["parameters"];

/**
 * Checks if the provided data is a valid JSON Web Signature Header Parameters object.
 *
 * @param parametersOrHeaderConstructor JSON Web Signature Header Parameters or JSON Web Signature Header Constructor.
 * @param parameters JSON Web Signature Header Parameters.
 * @returns Whether or not the provided data is a valid JSON Web Signature Header Parameters object.
 */
export function check<T extends JsonWebSignatureHeader = JsonWebSignatureHeader>(
  parametersOrHeaderConstructor: unknown,
  parameters?: unknown,
): parameters is T["parameters"] {
  const HeaderConstructor = Functions.isClass<T>(parametersOrHeaderConstructor)
    ? parametersOrHeaderConstructor
    : JsonWebSignatureHeader;

  parameters =
    arguments.length === 1 && !Functions.isClass(parametersOrHeaderConstructor)
      ? parametersOrHeaderConstructor
      : parameters;

  try {
    if (
      HeaderConstructor !== JsonWebSignatureHeader &&
      !(HeaderConstructor.prototype instanceof JsonWebSignatureHeader)
    ) {
      return false;
    }

    Reflect.construct(HeaderConstructor, [parameters]);

    return true;
  } catch {
    return false;
  }
}
