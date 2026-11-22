import { check } from "./check/check.ts";
import { create } from "./create/create.ts";
import { generate } from "./generate/generate.ts";
import { parse } from "./parse/parse.ts";
import { register } from "./register/register.ts";

interface JsonWebKeyMethods {
  /**
   * Checks if the provided data is a valid JSON Web Key Parameters object.
   *
   * @param parameters JSON Web Key Parameters.
   * @returns Whether or not the provided data is a valid JSON Web Key Parameters object.
   */
  readonly check: typeof check;

  /**
   * Creates a JSON Web Key based on the provided Parameters.
   *
   * @param parameters JSON Web Key Parameters.
   * @param additionalParameters Optional additional JSON Web Key Parameters.
   * @returns JSON Web Key.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key Parameters are invalid.
   */
  readonly create: typeof create;

  /**
   * Generates a JSON Web Key based on the provided options.
   *
   * @param keyType JSON Web Key Key Type.
   * @param options JSON Web Key Generation Options.
   * @param parameters Optional additional JSON Web Key Parameters.
   * @returns Generated JSON Web Key.
   * @throws {InvalidJsonWebKeyError} The provided additional JSON Web Key Parameters is invalid.
   * @throws {TypeError} One of the provided arguments is invalid.
   */
  readonly generate: typeof generate;

  /**
   * Parses the provided stringified JSON Web Key Parameters into a JSON Web Key.
   *
   * @param data Stringified JSON Web Key Parameters.
   * @param additionalParameters Optional additional JSON Web Key Parameters.
   * @returns Parsed JSON Web Key.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key Parameters is invalid.
   */
  readonly parse: typeof parse;

  /**
   * Registers the provided JSON Web Key Backend into the Registry.
   *
   * @param backend JSON Web Key Backend to be registered.
   * @throws {TypeError} The provided JSON Web Key Backend is invalid or is already registered.
   */
  readonly register: typeof register;
}

export const jwk: JsonWebKeyMethods = {
  check,
  create,
  generate,
  parse,
  register,
};

export { JsonWebKey } from "./jsonwebkey.ts";
export type { JsonWebKeyParameters } from "./jsonwebkey.parameters.ts";
