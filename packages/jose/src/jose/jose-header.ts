import type { X509Certificate } from "node:crypto";
import { URL } from "node:url";

import { Objects } from "@avarin/primitives/objects";
import { Strings } from "@avarin/primitives/strings";

import { InvalidJoseHeaderError } from "../errors/invalid-jose-header.error.ts";
import { jwk } from "../jwk/index.ts";
import type { JsonWebKey } from "../jwk/jsonwebkey.ts";
import type { JoseHeaderParameters } from "./jose-header.parameters.ts";

/**
 * Implementation of the JOSE Header.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4|RFC 7515 JOSE Header}
 * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4|RFC 7516 JOSE Header}
 */
export abstract class JoseHeader<T extends JoseHeaderParameters = JoseHeaderParameters> {
  /**
   * JOSE Header Parameters.
   */
  public readonly parameters: T;

  /**
   * JSON Web Key used by the JOSE Header.
   */
  #jsonWebKey!: JsonWebKey | null;

  /**
   * JSON Web Key X.509 Certificate Chain.
   */
  #certificateChain!: X509Certificate[] | null;

  /**
   * JSON Web Key used by the JOSE Header.
   */
  public get jsonWebKey(): JsonWebKey | null {
    if (typeof this.#jsonWebKey === "undefined") {
      this.#jsonWebKey = null;
    }

    return this.#jsonWebKey;
  }

  /**
   * JSON Web Key used by the JOSE Header.
   */
  public set jsonWebKey(jsonWebKey: JsonWebKey | null) {
    this.#jsonWebKey = jsonWebKey;
  }

  /**
   * JSON Web Key X.509 Certificate Chain.
   */
  public get certificateChain(): X509Certificate[] | null {
    if (typeof this.#certificateChain === "undefined") {
      this.#certificateChain = null;
    }

    return this.#certificateChain;
  }

  /**
   * JSON Web Key X.509 Certificate Chain.
   */
  public set certificateChain(certificateChain: X509Certificate[] | null) {
    this.#certificateChain = certificateChain;
  }

  /**
   * Instantiates a new JOSE Header.
   *
   * @param parameters JOSE Header Parameters.
   * @throws {InvalidJoseHeaderError} The provided JOSE Header Parameters is invalid.
   */
  public constructor(parameters: T) {
    this.validate(parameters);
    this.parameters = Objects.removeNullishValues(parameters);
  }

  /**
   * Validates the provided JOSE Header Parameters.
   *
   * @param parameters JOSE Header Parameters.
   * @throws {InvalidJoseHeaderError} The provided JOSE Header Parameters is invalid.
   */
  protected validate(parameters: T): void {
    if ("jku" in parameters && (!Strings.isNonEmpty(parameters.jku) || !URL.canParse(parameters.jku))) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "jku".');
    }

    if ("jwk" in parameters && !jwk.check(parameters.jwk)) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "jwk".');
    }

    if ("jku" in parameters && "jwk" in parameters) {
      throw new InvalidJoseHeaderError('Cannot have both "jku" and "jwk" JOSE Header Parameters.');
    }

    if ("kid" in parameters && !Strings.isNonEmpty(parameters.kid)) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "kid".');
    }

    if ("x5u" in parameters && (!Strings.isNonEmpty(parameters.x5u) || !URL.canParse(parameters.x5u))) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "x5u".');
    }

    if ("x5c" in parameters && !this.checkIfX5CIsANonEmptyArrayOfStrings(parameters.x5c)) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "x5c".');
    }

    if ("x5t" in parameters && !Strings.isNonEmpty(parameters.x5t)) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "x5t".');
    }

    if ("x5t#S256" in parameters && !Strings.isNonEmpty(parameters["x5t#S256"])) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "x5t#S256".');
    }

    if ("x5u" in parameters && "x5c" in parameters) {
      throw new InvalidJoseHeaderError('Cannot have both "x5u" and "x5c" JOSE Header Parameters.');
    }

    if (("x5t" in parameters || "x5t#S256" in parameters) && !("x5u" in parameters) && !("x5c" in parameters)) {
      throw new InvalidJoseHeaderError(
        "Cannot have an X.509 Certificate Thumbprint without an X.509 Certificate Chain.",
      );
    }

    if ("typ" in parameters && !Strings.isNonEmpty(parameters.typ)) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "typ".');
    }

    if ("cty" in parameters && !Strings.isNonEmpty(parameters.cty)) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "cty".');
    }

    if ("crit" in parameters) {
      if (!this.checkIfCritIsANonEmptyArrayOfStrings(parameters.crit)) {
        throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "crit".');
      }

      parameters.crit.forEach((parameter) => {
        if (!(parameter in parameters)) {
          throw new InvalidJoseHeaderError(`Missing required JOSE Header Parameter "${parameter}".`);
        }
      });
    }
  }

  // #region Helper Methods
  private checkIfX5CIsANonEmptyArrayOfStrings(x5c: unknown): x5c is string[] {
    return Array.isArray(x5c) && x5c.length > 0 && x5c.every((certificate) => Strings.isNonEmpty(certificate));
  }

  private checkIfCritIsANonEmptyArrayOfStrings(crit: unknown): crit is string[] {
    return Array.isArray(crit) && crit.length > 0 && crit.every((parameter) => Strings.isNonEmpty(parameter));
  }
  // #endregion
}
