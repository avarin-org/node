import type { X509Certificate } from "node:crypto";

import { Functions } from "@avarin/primitives/functions";
import { Strings } from "@avarin/primitives/strings";

import { InvalidJsonWebKeyError } from "../errors/invalid-jsonwebkey.error.ts";
import { JSONWEBKEY_BACKEND_REGISTRY } from "../jwa/jwk/jsonwebkey.backend.registry.ts";
import type { JsonWebKeyBackend } from "../jwa/jwk/jsonwebkey.backend.ts";
import type { JsonWebKeyParameters } from "./jsonwebkey.parameters.ts";

/**
 * Implementation of the JSON Web Key.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html|RFC 7517 JSON Web Key (JWK)}
 */
export class JsonWebKey<T extends JsonWebKeyParameters = JsonWebKeyParameters> {
  /**
   * JSON Web Key Backend.
   */
  readonly #backend: JsonWebKeyBackend<T>;

  /**
   * JSON Web Key X.509 Certificate Chain.
   */
  #certificateChain!: X509Certificate[] | null;

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
    if (typeof this.#certificateChain !== "undefined") {
      throw new TypeError("The X.509 Certificate Chain is already set.");
    }

    this.#certificateChain = certificateChain;
  }

  /**
   * JSON Web Key Parameters.
   */
  public get parameters(): T {
    return this.#backend.parameters;
  }

  /**
   * Instantiates a new JSON Web Key.
   *
   * @param parameters JSON Web Key Parameters.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key Parameters is invalid.
   */
  public constructor(parameters: T) {
    this.#backend = this.getJsonWebKeyBackend(parameters);
  }

  /**
   * Returns the JSON Web Key Parameters.
   *
   * @default exportPrivate false
   * @param exportPrivate Exports the private parameters of the JSON Web key.
   * @returns JSON Web Key Parameters.
   */
  public toJSON(exportPrivate = false): T {
    return this.#backend.toJSON(exportPrivate);
  }

  /**
   * Returns the JSON Web Key Backend based on the JSON Web Key Parameters.
   *
   * @param parameters JSON Web Key Parameters.
   * @returns JSON Web Key Backend.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key Parameters is invalid.
   */
  private getJsonWebKeyBackend(parameters: T): JsonWebKeyBackend<T> {
    if (!("kty" in parameters) || !Strings.isNonEmpty(parameters.kty)) {
      throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "kty".');
    }

    const Constructor = JSONWEBKEY_BACKEND_REGISTRY.find((backend) => backend.keyType === parameters.kty);

    if (!Functions.isClass(Constructor)) {
      throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "kty".');
    }

    return Reflect.construct(Constructor, [parameters]) as JsonWebKeyBackend<T>;
  }
}
