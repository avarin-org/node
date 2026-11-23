import { InvalidJsonWebKeySetError } from "../../errors/invalid-jsonwebkeyset.error.ts";
import { jwks } from "../../jwks/index.ts";
import type { JsonWebKeySet } from "../../jwks/jsonwebkeyset.ts";

/**
 * Fetches a JSON Web Key Set from the provided URL.
 *
 * @param url JSON Web Key Set URL.
 * @returns JSON Web Key Set.
 * @throws {InvalidJsonWebKeySetError} Failed to parse a JSON Web Key Set from the provided URL.
 */
export async function getJsonWebKeySetFromUrl(url: string): Promise<JsonWebKeySet> {
  const response = await globalThis.fetch(url);

  if (!response.ok) {
    throw new InvalidJsonWebKeySetError("Failed to parse a JSON Web Key Set from the provided URL.");
  }

  const stringifiedJsonWebKeySet = await response.text();

  return await jwks.parse(stringifiedJsonWebKeySet);
}
