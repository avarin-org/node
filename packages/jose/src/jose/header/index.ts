import { check } from "./check/check.ts";
import { create } from "./create/create.ts";
import { parse } from "./parse/parse.ts";

interface JoseHeaderMethods {
  /**
   * Checks if the provided data is a valid JOSE Header Parameters object.
   *
   * @param HeaderConstructor JOSE Header Constructor.
   * @param parameters JOSE Header Parameters.
   * @returns Whether or not the provided data is a valid JOSE Header Parameters object.
   */
  readonly check: typeof check;

  /**
   * Creates a JOSE Header based on the provided JOSE Header Parameters.
   *
   * @param HeaderConstructor JOSE Header Constructor.
   * @param parameters JOSE Header Parameters.
   * @param additionalParameters Optional additional JOSE Header Parameters.
   * @returns JOSE Header.
   * @throws {InvalidJoseHeaderError} The provided JOSE Header Parameters is invalid.
   * @throws {TypeError} One of the provided arguments is invalid.
   */
  readonly create: typeof create;

  /**
   * Parses the provided stringified JOSE Header Parameters into a JOSE Header.
   *
   * @param HeaderConstructor JOSE Header Constructor.
   * @param data Stringified JOSE Header Parameters.
   * @param additionalParameters Optional additional JOSE Header Parameters.
   * @returns JOSE Header.
   * @throws {InvalidJoseHeaderError} The provided JOSE Header Parameters is invalid.
   * @throws {TypeError} One of the provided arguments is invalid.
   */
  readonly parse: typeof parse;
}

export const header: JoseHeaderMethods = {
  check,
  create,
  parse,
};
