import { check } from "./check/check.ts";
import { create } from "./create/create.ts";
import { parse } from "./parse/parse.ts";

interface JsonWebSignatureHeaderMethods {
  /**
   * Checks if the provided data is a valid JSON Web Signature Header Parameters object.
   *
   * @param parameters JSON Web Signature Header Parameters.
   * @returns Whether or not the provided data is a valid JSON Web Signature Header Parameters object.
   */
  readonly check: typeof check;

  /**
   * Creates a JSON Web Signature Header based on the provided JSON Web Signature Header Parameters.
   *
   * @param parameters JSON Web Signature Header Parameters.
   * @param additionalParameters Optional additional JSON Web Signature Parameters.
   * @returns JSON Web Signature Header.
   * @throws {InvalidJoseHeaderError} The provided JSON Web Signature Header Parameters is invalid.
   */
  readonly create: typeof create;

  /**
   * Parses the provided stringified JSON Web Signature Header Parameters into a JSON Web Signature Header.
   *
   * @param data Stringified JSON Web Signature Header Parameters.
   * @param additionalParameters Optional additional JSON Web Signature Header Parameters.
   * @returns Parsed JSON Web Signature Header.
   * @throws {InvalidJoseHeaderError} The provided JSON Web Signature Header Parameters is invalid.
   */
  readonly parse: typeof parse;
}

export const header: JsonWebSignatureHeaderMethods = {
  check,
  create,
  parse,
};
