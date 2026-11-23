import { create } from "./create/create.ts";
import { parse } from "./parse/parse.ts";

interface JsonWebKeySetMethods {
  /**
   * Creates a JSON Web Key Set based on the provided JSON Web Key Set Parameters or JSON Web Keys.
   *
   * @param parametersOrKeys JSON Web Key Set Parameters or JSON Web Keys.
   * @returns JSON Web Key Set.
   * @throws {InvalidJsonWebKeySetError} The provided JSON Web Key Set Parameters is invalid or the provided JSON Web
   *   Keys contain duplicate entries.
   */
  readonly create: typeof create;

  /**
   * Parses the provided stringified JSON Web Key Set Parameters into a JSON Web Key Set.
   *
   * @param data Stringified JSON Web Key Set Parameters.
   * @returns Parsed JSON Web Key Set.
   * @throws {InvalidJsonWebKeySetError} The provided JSON Web Key Set Parameters is invalid.
   */
  readonly parse: typeof parse;
}

export const jwks: JsonWebKeySetMethods = {
  create,
  parse,
};

export { JsonWebKeySet } from "./jsonwebkeyset.ts";
export type { JsonWebKeySetParameters } from "./jsonwebkeyset.parameters.ts";
