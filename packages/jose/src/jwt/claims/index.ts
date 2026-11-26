import { check } from "./check/check.ts";
import { create } from "./create/create.ts";
import { parse } from "./parse/parse.ts";

interface JsonWebTokenClaimsMethods {
  /**
   * Checks if the provided data is a valid JSON Web Token Claims Parameters object.
   *
   * @param parametersOrClaimsConstructor JSON Web Token Claims Parameters or JSON Web Token Claims Constructor.
   * @param parameters JSON Web Token Claims Parameters.
   * @returns Whether or not the provided data is a valid JSON Web Token Claims Parameters object.
   */
  readonly check: typeof check;

  /**
   * Creates a JSON Web Token Claims based on the provided JSON Web Token Claims Parameters.
   *
   * @param parametersOrClaimsConstructor JSON Web Token Claims Parameters or JSON Web Token Claims Constructor.
   * @param parametersOrAdditionalParameters JSON Web Token Claims Parameters or Optional additional JSON Web Token
   *   Claims Parameters.
   * @param additionalParameters Optional additional JSON Web Token Claims Parameters.
   * @returns JSON Web Token Claims.
   * @throws {InvalidJsonWebTokenClaimsError} The provided JSON Web Token Claims Parameters is invalid.
   * @throws {TypeError} One of the provided arguments is invalid.
   */
  readonly create: typeof create;

  /**
   * Parses the provided stringified JSON Web Token Claims Parameters into a JSON Web Token Claims.
   *
   * @param dataOrClaimsConstructor Stringified JSON Web Token Claims Parameters or JSON Web Token Claims Constructor.
   * @param dataOrAdditionalParameters Stringified JSON Web Token Claims Parameters or Optional additional JSON Web
   *   Token Claims Parameters.
   * @param additionalParameters Optional additional JSON Web Token Claims Parameters.
   * @returns JSON Web Token Claims.
   * @throws {InvalidJsonWebTokenClaimsError} The provided JSON Web Token Claims Parameters is invalid.
   */
  readonly parse: typeof parse;
}

export const claims: JsonWebTokenClaimsMethods = {
  check,
  create,
  parse,
};
