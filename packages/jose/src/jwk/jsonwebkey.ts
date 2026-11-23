import type { KeyObject, X509Certificate } from "node:crypto";

import { Objects } from "@avarin/primitives/objects";
import { Strings } from "@avarin/primitives/strings";

import { InvalidJsonWebKeyError } from "../errors/invalid-jsonwebkey.error.ts";
import { KeyTypeBackend } from "../jwa/jwk/key-type.backend.js";
import { KEY_TYPE_BACKEND_REGISTRY } from "../jwa/jwk/key-type.backend.registry.ts";
import type { JsonWebKeyParameters } from "./jsonwebkey.parameters.ts";

/**
 * Implementation of the JSON Web Key.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html|RFC 7517 JSON Web Key (JWK)}
 */
export class JsonWebKey<T extends JsonWebKeyParameters = JsonWebKeyParameters> {
  /**
   * Key Type Backend.
   */
  readonly #backend: KeyTypeBackend<T>;

  /**
   * JSON Web Key X.509 Certificate Chain.
   */
  #certificateChain!: X509Certificate[] | null;

  /**
   * Native Crypto Key.
   */
  readonly #cryptoKey: KeyObject;

  /**
   * JSON Web Key Parameters.
   */
  readonly #parameters: T;

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
   * Native Crypto Key.
   */
  public get cryptoKey(): KeyObject {
    return this.#cryptoKey;
  }

  /**
   * JSON Web Key Parameters.
   */
  public get parameters(): T {
    return this.#parameters;
  }

  /**
   * Instantiates a new JSON Web Key.
   *
   * @param parameters JSON Web Key Parameters.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key Parameters is invalid.
   */
  public constructor(parameters: T) {
    this.#backend = this.getKeyTypeBackend(parameters);
    this.#cryptoKey = this.#backend.getCryptoKey(parameters);
    this.#parameters = Objects.removeNullishValues(globalThis.structuredClone(parameters));
  }

  /**
   * Returns the JSON Web Key Parameters.
   *
   * @default exportPrivate false
   * @param exportPrivate Exports the private parameters of the JSON Web key.
   * @returns JSON Web Key Parameters.
   */
  public toJSON(exportPrivate = false): T {
    const privateParameters = this.#backend.getPrivateParameters();
    let entries = Object.entries(this.#parameters);

    if (!exportPrivate) {
      entries = entries.filter(([parameter]) => !privateParameters.includes(parameter));
    }

    return Object.fromEntries(entries) as T;
  }

  /**
   * Returns the Key Type Backend based on the JSON Web Key Parameters.
   *
   * @param parameters JSON Web Key Parameters.
   * @returns Key Type Backend.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key Parameters is invalid.
   */
  private getKeyTypeBackend(parameters: T): KeyTypeBackend<T> {
    if (!("kty" in parameters) || !Strings.isNonEmpty(parameters.kty)) {
      throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "kty".');
    }

    const keyTypeBackend = KEY_TYPE_BACKEND_REGISTRY.find((backend) => backend.name === parameters.kty);

    if (!(keyTypeBackend instanceof KeyTypeBackend)) {
      throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "kty".');
    }

    return keyTypeBackend as KeyTypeBackend<T>;
  }
}
