import { Objects } from "@avarin/primitives/objects";
import { Strings } from "@avarin/primitives/strings";

import { InvalidJsonWebKeySetError } from "../../errors/invalid-jsonwebkeyset.error.ts";
import { jwk } from "../../jwk/index.ts";
import { JsonWebKey } from "../../jwk/jsonwebkey.ts";
import type { JsonWebKeySetParameters } from "../jsonwebkeyset.parameters.ts";
import { JsonWebKeySet } from "../jsonwebkeyset.ts";

/**
 * Validates the provided JSON Web Keys.
 *
 * @param keys JSON Web Keys.
 * @returns Provided JSON Web Keys after validation.
 * @throws {InvalidJsonWebKeySetError} The provided JSON Web Keys contain duplicate entries.
 */
function validateJsonWebKeys(keys: JsonWebKey[]): JsonWebKey[] {
  if (
    keys.length === 0 ||
    keys.some((key) => !(key instanceof JsonWebKey) || !Strings.isNonEmpty(key.parameters.kid))
  ) {
    throw new InvalidJsonWebKeySetError("The provided JSON Web Keys is invalid.");
  }

  const identifiers = keys.map((key) => key.parameters.kid!);

  if (new Set(identifiers).size !== identifiers.length) {
    throw new InvalidJsonWebKeySetError("The use of duplicate JSON Web Keys is forbidden.");
  }

  return keys;
}

/**
 * Validates the provided JSON Web Key Set Parameters.
 *
 * @param parameters JSON Web Key Set Parameters.
 * @returns JSON Web Keys from the provided JSON Web Key Set Parameters.
 * @throws {InvalidJsonWebKeySetError} The provided JSON Web Key Set Parameters is invalid.
 */
async function validateJsonWebKeySetParameters(parameters: JsonWebKeySetParameters): Promise<JsonWebKey[]> {
  if (!Objects.isPlain(parameters)) {
    throw new InvalidJsonWebKeySetError("The provided JSON Web Key Set Parameters is invalid.");
  }

  if (!Array.isArray(parameters.keys) || parameters.keys.length === 0) {
    throw new InvalidJsonWebKeySetError('Invalid JSON Web Key Set Parameter "keys".');
  }

  try {
    const keys = await Promise.all(parameters.keys.map(async (key) => await jwk.create(key)));
    return validateJsonWebKeys(keys);
  } catch (error: unknown) {
    throw new InvalidJsonWebKeySetError('Invalid JSON Web Key Set Parameter "keys".', { cause: error });
  }
}

/**
 * Creates a JSON Web Key Set based on the provided JSON Web Key Set Parameters.
 *
 * @param parameters JSON Web Key Set Parameters.
 * @returns JSON Web Key Set.
 * @throws {InvalidJsonWebKeySetError} The provided JSON Web Key Set Parameters is invalid.
 */
export async function create(parameters: JsonWebKeySetParameters): Promise<JsonWebKeySet>;

/**
 * Creates a JSON Web Key Set based on the provided JSON Web Keys.
 *
 * @param keys JSON Web Keys.
 * @returns JSON Web Key Set.
 * @throws {InvalidJsonWebKeySetError} The provided JSON Web Keys contain duplicate entries.
 */
export async function create(keys: JsonWebKey[]): Promise<JsonWebKeySet>;

/**
 * Creates a JSON Web Key Set based on the provided JSON Web Key Set Parameters or JSON Web Keys.
 *
 * @param parametersOrKeys JSON Web Key Set Parameters or JSON Web Keys.
 * @returns JSON Web Key Set.
 * @throws {InvalidJsonWebKeySetError} The provided JSON Web Key Set Parameters is invalid or the provided JSON Web Keys
 *   contain duplicate entries.
 */
export async function create(parametersOrKeys: JsonWebKeySetParameters | JsonWebKey[]): Promise<JsonWebKeySet> {
  const keys = Array.isArray(parametersOrKeys)
    ? validateJsonWebKeys(parametersOrKeys)
    : await validateJsonWebKeySetParameters(parametersOrKeys);

  return new JsonWebKeySet(keys);
}
