import { create } from "./create/create.ts";

interface JsonWebKeySetMethods {
  /**
   * Creates a JSON Web Key Set based on the provided JSON Web Key Set Parameters or JSON Web Keys.
   *
   * @param parametersOrKeys JSON Web Key Set Parameters or JSON Web Keys.
   * @returns JSON Web Key Set.
   * @throws {InvalidJsonWebKeySetError} The provided JSON Web Key Set Parameters are invalid or the provided JSON Web
   * @throws {TypeError} The provided JSON Web Key Set Parameters or JSON Web Keys is invalid. Keys contain duplicate
   *   entries.
   */
  readonly create: typeof create;
}

export const jwks: JsonWebKeySetMethods = {
  create,
};

export { JsonWebKeySet } from "./jsonwebkeyset.ts";
export type { JsonWebKeySetParameters } from "./jsonwebkeyset.parameters.ts";
