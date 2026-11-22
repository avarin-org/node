import { JSON } from "@avarin/primitives/json";

import { InvalidJsonWebKeySetError } from "../../errors/invalid-jsonwebkeyset.error.ts";
import { create } from "../create/create.ts";
import type { JsonWebKeySetParameters } from "../jsonwebkeyset.parameters.ts";
import type { JsonWebKeySet } from "../jsonwebkeyset.ts";

/**
 * Parses the provided stringified JSON Web Key Set Parameters into a JSON Web Key Set.
 *
 * @param data Stringified JSON Web Key Set Parameters.
 * @returns Parsed JSON Web Key Set.
 * @throws {InvalidJsonWebKeySetError} The provided JSON Web Key Set Parameters is invalid.
 */
export async function parse(data: string): Promise<JsonWebKeySet> {
  try {
    return await create(JSON.parse<JsonWebKeySetParameters>(data));
  } catch (error: unknown) {
    throw new InvalidJsonWebKeySetError("The provided JSON Web Key Set Parameters is invalid.", { cause: error });
  }
}
