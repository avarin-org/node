import { check } from "./check/check.ts";
import { create } from "./create/create.ts";
import { parse } from "./parse/parse.ts";

interface JsonWebEncryptionHeaderMethods {
  /**
   * Checks if the provided data is a valid JSON Web Encryption Header Parameters object.
   *
   * @param parametersOrHeaderConstructor JSON Web Encryption Header Parameters or JSON Web Encryption Header
   *   Constructor.
   * @param parameters JSON Web Encryption Header Parameters.
   * @returns Whether or not the provided data is a valid JSON Web Encryption Header Parameters object.
   */
  readonly check: typeof check;

  /**
   * Creates a JSON Web Encryption Header based on the provided JSON Web Encryption Header Parameters.
   *
   * @param parametersOrHeaderConstructor JSON Web Encryption Header Parameters or JSON Web Encryption Header
   *   Constructor.
   * @param parametersOrAdditionalParameters JSON Web Encryption Header Parameters or Optional additional JSON Web
   *   Encryption Header Parameters.
   * @param additionalParameters Optional additional JSON Web Encryption Header Parameters.
   * @returns JSON Web Encryption Header.
   * @throws {InvalidJoseHeaderError} The provided JSON Web Encryption Header Parameters is invalid.
   * @throws {TypeError} One of the provided arguments is invalid.
   */
  readonly create: typeof create;

  /**
   * Parses the provided stringified JSON Web Encryption Header Parameters into a JSON Web Encryption Header.
   *
   * @param dataOrHeaderConstructor Stringified JSON Web Encryption Header Parameters or JSON Web Encryption Header
   *   Constructor.
   * @param dataOrAdditionalParameters Stringified JSON Web Encryption Header Parameters or Optional additional JSON Web
   *   Encryption Header Parameters.
   * @param additionalParameters Optional additional JSON Web Encryption Header Parameters.
   * @returns JSON Web Encryption Header.
   * @throws {InvalidJoseHeaderError} The provided JSON Web Encryption Header Parameters is invalid.
   */
  readonly parse: typeof parse;
}

export const header: JsonWebEncryptionHeaderMethods = {
  check,
  create,
  parse,
};
