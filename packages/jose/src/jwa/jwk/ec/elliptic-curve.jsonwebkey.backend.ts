import { createPrivateKey, createPublicKey, generateKeyPair } from "node:crypto";
import type { JsonWebKeyInput, KeyObject } from "node:crypto";
import { promisify } from "node:util";

import { Objects } from "@avarin/primitives/objects";
import { Strings } from "@avarin/primitives/strings";

import { InvalidJsonWebKeyError } from "../../../errors/invalid-jsonwebkey.error.ts";
import type { JsonWebKeyParameters } from "../../../jwk/jsonwebkey.parameters.ts";
import type { JsonWebKey } from "../../../jwk/jsonwebkey.ts";
import { JsonWebKeyBackend } from "../jsonwebkey.backend.ts";
import type { EllipticCurveJsonWebKeyParameters } from "./elliptic-curve.jsonwebkey.parameters.ts";
import type { EllipticCurve } from "./elliptic-curve.type.ts";
import type { GenerateEllipticCurveJsonWebKeyOptions } from "./generate-elliptic-curve-jsonwebkey.options.ts";

const generateKeyPairAsync = promisify(generateKeyPair);

/**
 * Implementation of the Elliptic Curve JSON Web Key Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2|RFC 7518 Parameters for Elliptic Curve Keys}
 */
export class EllipticCurveJsonWebKeyBackend extends JsonWebKeyBackend<EllipticCurveJsonWebKeyParameters> {
  /**
   * Supported JSON Web Key Elliptic Curves.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.1.1|RFC 7518 "crv" (Curve) Parameter}
   */
  static readonly #curves: Record<EllipticCurve, string> = {
    "P-256": "prime256v1",
    "P-384": "secp384r1",
    "P-521": "secp521r1",
  };

  /**
   * JSON Web Key Key Type supported by the JSON Web Key Backend.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.1|RFC 7517 "kty" (Key Type) Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.1|RFC 7518 "kty" (Key Type) Parameter Values}
   */
  public static override readonly keyType = "EC" as const;

  /**
   * Generates a JSON Web Key based on the provided options.
   *
   * @param options JSON Web Key Generation Options.
   * @param parameters Optional additional JSON Web Key Parameters.
   * @returns Generated JSON Web Key.
   * @throws {InvalidJsonWebKeyError} The provided additional JSON Web Key Parameters is invalid.
   * @throws {TypeError} The provided Generation Options is invalid.
   */
  public static override async generate(
    options: GenerateEllipticCurveJsonWebKeyOptions,
    parameters: Partial<JsonWebKeyParameters> = {},
  ): Promise<JsonWebKey<EllipticCurveJsonWebKeyParameters>> {
    if (!Objects.isPlain(options)) {
      throw new TypeError("The provided Elliptic Curve JSON Web Key Generation Options is invalid.");
    }

    if (
      !("curve" in options) ||
      !Strings.isNonEmpty(options.curve) ||
      !(options.curve in EllipticCurveJsonWebKeyBackend.#curves)
    ) {
      throw new TypeError('The provided Elliptic Curve JSON Web Key Generation Option "curve" is invalid.');
    }

    const { privateKey } = await generateKeyPairAsync("ec", {
      namedCurve: EllipticCurveJsonWebKeyBackend.#curves[options.curve]!,
    });

    const jsonWebKeyParameters = {
      ...parameters,
      ...privateKey.export({ format: "jwk" }),
    } as EllipticCurveJsonWebKeyParameters;

    const { create } = await import("../../../jwk/create/create.ts");

    return await create(jsonWebKeyParameters);
  }

  /**
   * Creates a native Crypto Key.
   *
   * @returns Native Crypto Key.
   */
  public getCryptoKey(): KeyObject {
    const input: JsonWebKeyInput = { format: "jwk", key: this.parameters };
    return "d" in this.parameters ? createPrivateKey(input) : createPublicKey(input);
  }

  /**
   * Returns the JSON Web Key Parameters.
   *
   * @default exportPrivate false
   * @param exportPrivate Exports the private parameters of the JSON Web key.
   * @returns JSON Web Key Parameters.
   */
  public toJSON(exportPrivate = false): EllipticCurveJsonWebKeyParameters {
    const parameters = globalThis.structuredClone(this.parameters);

    if (!exportPrivate) {
      Reflect.deleteProperty(parameters, "d");
    }

    return parameters;
  }

  /**
   * Validates the provided JSON Web Key Parameters.
   *
   * @param parameters JSON Web Key Parameters.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key Parameters is invalid.
   */
  protected override validate(parameters: EllipticCurveJsonWebKeyParameters): void {
    if (!Strings.isNonEmpty(parameters.crv) || !(parameters.crv in EllipticCurveJsonWebKeyBackend.#curves)) {
      throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "crv".');
    }

    if (!Strings.isNonEmpty(parameters.x)) {
      throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "x".');
    }

    if (!Strings.isNonEmpty(parameters.y)) {
      throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "y".');
    }

    if ("d" in parameters && !Strings.isNonEmpty(parameters.d)) {
      throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "d".');
    }

    super.validate(parameters);
  }
}
