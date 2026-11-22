import { JSON } from "@avarin/primitives/json";

import { InvalidJsonWebKeyError } from "../../errors/invalid-jsonwebkey.error.ts";
import { create } from "../create/create.ts";
import type { JsonWebKeyParameters } from "../jsonwebkey.parameters.ts";
import type { JsonWebKey } from "../jsonwebkey.ts";

/**
 * Parses the provided stringified JSON Web Key Parameters into a JSON Web Key.
 *
 * @param data Stringified JSON Web Key Parameters.
 * @param additionalParameters Optional additional JSON Web Key Parameters.
 * @returns Parsed JSON Web Key.
 * @throws {InvalidJsonWebKeyError} The provided JSON Web Key Parameters is invalid.
 */
export async function parse<T extends JsonWebKeyParameters = JsonWebKeyParameters>(
  data: string,
  additionalParameters: Partial<JsonWebKeyParameters> = {},
): Promise<JsonWebKey<T>> {
  try {
    return await create(JSON.parse<T>(data), additionalParameters);
  } catch (error: unknown) {
    throw new InvalidJsonWebKeyError("The provided JSON Web Key Parameters is invalid.", { cause: error });
  }
}
