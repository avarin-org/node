import { check } from "./check/check.ts";
import { create } from "./create/create.ts";
import { parse } from "./parse/parse.ts";

interface JsonWebSignatureHeaderMethods {
  /**
   * Checks if the provided data is a valid JSON Web Signature Header Parameters object.
   *
   * @param parametersOrHeaderConstructor JSON Web Signature Header Parameters or JSON Web Signature Header Constructor.
   * @param parameters JSON Web Signature Header Parameters.
   * @returns Whether or not the provided data is a valid JSON Web Signature Header Parameters object.
   */
  readonly check: typeof check;

  /**
   * Creates a JSON Web Signature Header based on the provided JSON Web Signature Header Parameters.
   *
   * @param parametersOrHeaderConstructor JSON Web Signature Header Parameters or JSON Web Signature Header Constructor.
   * @param parametersOrAdditionalParameters JSON Web Signature Header Parameters or Optional additional JSON Web
   *   Signature Header Parameters.
   * @param additionalParameters Optional additional JSON Web Signature Header Parameters.
   * @returns JSON Web Signature Header.
   * @throws {InvalidJoseHeaderError} The provided JSON Web Signature Header Parameters is invalid.
   * @throws {TypeError} One of the provided arguments is invalid.
   */
  readonly create: typeof create;

  /**
   * Parses the provided stringified JSON Web Signature Header Parameters into a JSON Web Signature Header.
   *
   * @param dataOrHeaderConstructor Stringified JSON Web Signature Header Parameters or JSON Web Signature Header
   *   Constructor.
   * @param dataOrAdditionalParameters Stringified JSON Web Signature Header Parameters or Optional additional JSON Web
   *   Signature Header Parameters.
   * @param additionalParameters Optional additional JSON Web Signature Header Parameters.
   * @returns JSON Web Signature Header.
   * @throws {InvalidJoseHeaderError} The provided JSON Web Signature Header Parameters is invalid.
   */
  readonly parse: typeof parse;
}

export const header: JsonWebSignatureHeaderMethods = {
  check,
  create,
  parse,
};
