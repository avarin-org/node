import { Buffer } from "node:buffer";
import { isDeepStrictEqual } from "node:util";

import { JSON } from "@avarin/primitives/json";
import { Objects } from "@avarin/primitives/objects";
import { Strings } from "@avarin/primitives/strings";

import { InvalidJsonWebTokenClaimsError } from "../../errors/invalid-jsonwebtoken-claims.error.ts";
import type { JsonWebTokenClaimValidationOptions, JsonWebTokenClaimsOptions } from "./jsonwebtoken.claims.options.ts";
import type { JsonWebTokenClaimsParameters } from "./jsonwebtoken.claims.parameters.ts";

/**
 * Implementation of the JSON Web Token Claims.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7519.html#section-4|RFC 7519 JWT Claims}
 */
export class JsonWebTokenClaims<T extends JsonWebTokenClaimsParameters = JsonWebTokenClaimsParameters> {
  /**
   * JSON Web Token Claims.
   */
  public readonly parameters: T;

  /**
   * Indicates if the value of the JSON Web Token Claim "exp" should be ignored.
   */
  readonly #ignoreExpired: boolean = false;

  /**
   * Instantiates a new JSON Web Token Claims.
   *
   * @param parameters JSON Web Token Claims Parameters.
   * @param options JSON Web Token Claims Options.
   * @throws {InvalidJsonWebTokenClaimsError} The provided JSON Web Token Claims Parameters is invalid.
   * @throws {TypeError} One of the provided arguments is invalid.
   */
  public constructor(parameters: T, options: JsonWebTokenClaimsOptions = {}) {
    this.validateOptions(options);

    this.#ignoreExpired = options.ignoreExpired ?? false;
    this.validate(parameters);

    if ("validationOptions" in options) {
      this.validateClaimsOptions(parameters, options.validationOptions);
    }

    this.parameters = Objects.removeNullishValues(parameters);
  }

  /**
   * Returns the string representation of the JSON Web Token Claims.
   *
   * @returns String representation of the JSON Web Token Claims.
   */
  public toString(): string {
    return JSON.stringify(this.parameters);
  }

  /**
   * Returns the buffer representation of the JSON Web Token Claims.
   *
   * @returns Buffer representation of the JSON Web Token Claims.
   */
  public toBuffer(): Buffer {
    return Buffer.from(this.toString(), "utf8");
  }

  /**
   * Validates the provided JSON Web Token Claims Parameters.
   *
   * @param parameters JSON Web Token Claims Parameters.
   * @throws {InvalidJsonWebTokenClaimsError} The provided JSON Web Token Claims Parameters is invalid.
   * @throws {TypeError} The provided JSON Web Token Claims Parameters is invalid.
   */
  protected validate(parameters: T): void {
    if (!Objects.isPlain(parameters)) {
      throw new TypeError("The provided JSON Web Token Claims Parameters is invalid.");
    }

    const now = Math.floor(Date.now() / 1000);

    if ("iss" in parameters && !Strings.isNonEmpty(parameters.iss)) {
      throw new InvalidJsonWebTokenClaimsError('Invalid JSON Web Token Claim "iss".');
    }

    if ("sub" in parameters && !Strings.isNonEmpty(parameters.sub)) {
      throw new InvalidJsonWebTokenClaimsError('Invalid JSON Web Token Claim "sub".');
    }

    if ("aud" in parameters) {
      if (!Strings.isNonEmpty(parameters.aud) && !Array.isArray(parameters.aud)) {
        throw new InvalidJsonWebTokenClaimsError('Invalid JSON Web Token Claim "aud".');
      }

      if (
        Array.isArray(parameters.aud) &&
        (parameters.aud.length === 0 ||
          parameters.aud.some((aud) => !Strings.isNonEmpty(aud)) ||
          parameters.aud.length !== new Set(parameters.aud).size)
      ) {
        throw new InvalidJsonWebTokenClaimsError('Invalid JSON Web Token Claim "aud".');
      }
    }

    if (
      "exp" in parameters &&
      (typeof parameters.exp !== "number" ||
        !Number.isSafeInteger(parameters.exp) ||
        (!this.#ignoreExpired && parameters.exp < now))
    ) {
      throw new InvalidJsonWebTokenClaimsError('Invalid JSON Web Token Claim "exp".');
    }

    if (
      "nbf" in parameters &&
      (typeof parameters.nbf !== "number" || !Number.isSafeInteger(parameters.nbf) || parameters.nbf > now)
    ) {
      throw new InvalidJsonWebTokenClaimsError('Invalid JSON Web Token Claim "nbf".');
    }

    if ("iat" in parameters && (typeof parameters.iat !== "number" || !Number.isSafeInteger(parameters.iat))) {
      throw new InvalidJsonWebTokenClaimsError('Invalid JSON Web Token Claim "iat".');
    }

    if ("jti" in parameters && !Strings.isNonEmpty(parameters.jti)) {
      throw new InvalidJsonWebTokenClaimsError('Invalid JSON Web Token Claim "jti".');
    }
  }

  /**
   * Validates the provided JSON Web Token Claims Options.
   *
   * @param options JSON Web Token Claims Options to be validated.
   * @throws {TypeError} The provided JSON Web Token Claims Options is invalid.
   */
  private validateOptions(options: JsonWebTokenClaimsOptions): void {
    if (!Objects.isPlain(options)) {
      throw new TypeError("The provided JSON Web Token Claims Options is invalid.");
    }

    if ("ignoreExpired" in options && typeof options.ignoreExpired !== "boolean") {
      throw new TypeError('The provided JSON Web Token Claims Option "ignoreExpired" is invalid.');
    }

    if ("validationOptions" in options) {
      if (!Objects.isPlain(options.validationOptions)) {
        throw new TypeError('The provided JSON Web Token Claims Option "validationOptions" is invalid.');
      }

      Object.values(options.validationOptions).forEach((option) => {
        if (!Objects.isPlain(option)) {
          return;
        }

        if ("essential" in option && typeof option.essential !== "boolean") {
          throw new TypeError('The provided JSON Web Token Claim Validation Option "essential" is invalid.');
        }

        if ("value" in option && "values" in option) {
          throw new TypeError('Cannot have both "value" and "values" JSON Web Token Claim Validation Options.');
        }

        if ("values" in option && (!Array.isArray(option.values) || option.values.length === 0)) {
          throw new TypeError('The provided JSON Web Token Claim Validation Option "values" is invalid.');
        }
      });
    }
  }

  /**
   * Validates the provided JSON Web Token Claims Parameters based on the provided Options.
   *
   * @param parameters JSON Web Token Claims Parameters.
   * @param options Dictionary used to validate the provided JSON Web Token Claims Parameters.
   * @throws {InvalidJsonWebTokenClaimsError} A JSON Web Token Claim failed the required validation.
   */
  private validateClaimsOptions(parameters: T, options: NodeJS.Dict<JsonWebTokenClaimValidationOptions | null>): void {
    Object.entries(options).forEach(([claim, option]) => {
      if (!Objects.isPlain(option)) {
        return;
      }

      if (option.essential === true && !(claim in parameters)) {
        throw new InvalidJsonWebTokenClaimsError(`Missing required JSON Web Token Claim "${claim}".`);
      }

      if ("value" in option) {
        if (option.essential === false && !(claim in parameters)) {
          return;
        }

        if (!isDeepStrictEqual(parameters[claim], option.value, { skipPrototype: true })) {
          throw new InvalidJsonWebTokenClaimsError(`Unexpected value for JSON Web Token Claim "${claim}".`);
        }
      }

      if ("values" in option) {
        if (option.essential === false && !(claim in parameters)) {
          return;
        }

        if (!option.values.some((value) => isDeepStrictEqual(value, parameters[claim], { skipPrototype: true }))) {
          throw new InvalidJsonWebTokenClaimsError(`Unexpected value for JSON Web Token Claim "${claim}".`);
        }
      }
    });
  }
}
