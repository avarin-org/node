import { Buffer } from "node:buffer";
import { createPrivateKey, createPublicKey, generateKeyPair } from "node:crypto";
import type { JsonWebKeyInput, KeyObject } from "node:crypto";
import { promisify } from "node:util";

import { Objects } from "@avarin/primitives/objects";
import { Strings } from "@avarin/primitives/strings";

import { InvalidJsonWebKeyError } from "../../../errors/invalid-jsonwebkey.error.ts";
import type { JsonWebKeyParameters } from "../../../jwk/jsonwebkey.parameters.ts";
import type { JsonWebKey } from "../../../jwk/jsonwebkey.ts";
import { KeyTypeBackend } from "../key-type.backend.ts";
import type { GenerateRsaJsonWebKeyOptions } from "./generate-rsa-jsonwebkey.options.ts";
import type { RsaJsonWebKeyParameters } from "./rsa.jsonwebkey.parameters.ts";

const generateKeyPairAsync = promisify(generateKeyPair);

/**
 * Implementation of the RSA Key Type Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3|RFC 7518 Parameters for RSA Keys}
 */
export class RsaKeyTypeBackend extends KeyTypeBackend<RsaJsonWebKeyParameters> {
  /**
   * JSON Web Key Key Type.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.1|RFC 7517 "kty" (Key Type) Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.1|RFC 7518 "kty" (Key Type) Parameter Values}
   */
  public readonly name = "RSA" as const;

  /**
   * JSON Web Key Private Parameters.
   */
  readonly #privateParameters: string[] = ["d", "p", "q", "dp", "dq", "qi"];

  /**
   * Generates a JSON Web Key based on the provided options.
   *
   * @param options JSON Web Key Generation Options.
   * @param parameters Optional additional JSON Web Key Parameters.
   * @returns Generated JSON Web Key.
   * @throws {InvalidJsonWebKeyError} The provided additional JSON Web Key Parameters is invalid.
   * @throws {TypeError} The provided Generation Options is invalid.
   */
  public async generate(
    options: GenerateRsaJsonWebKeyOptions,
    parameters: Partial<JsonWebKeyParameters> = {},
  ): Promise<JsonWebKey<RsaJsonWebKeyParameters>> {
    if (!Objects.isPlain(options)) {
      throw new TypeError("The provided RSA JSON Web Key Generation Options is invalid.");
    }

    if (!("modulus" in options) || !Number.isSafeInteger(options.modulus) || options.modulus < 2048) {
      throw new TypeError('The provided RSA JSON Web Key Generation Option "modulus" is invalid.');
    }

    if ("publicExponent" in options && (!Number.isSafeInteger(options.publicExponent) || options.publicExponent < 1)) {
      throw new TypeError('The provided RSA JSON Web Key Generation Option "publicExponent" is invalid.');
    }

    const { privateKey } = await generateKeyPairAsync("rsa", {
      modulusLength: options.modulus,
      publicExponent: options.publicExponent ?? 0x01_00_01,
    });

    const jsonWebKeyParameters = {
      ...parameters,
      ...privateKey.export({ format: "jwk" }),
    } as RsaJsonWebKeyParameters;

    const { create } = await import("../../../jwk/create/create.ts");

    return await create(jsonWebKeyParameters);
  }

  /**
   * Creates a native Crypto Key.
   *
   * @param parameters JSON Web Key Parameters.
   * @returns Native Crypto Key.
   */
  public getCryptoKey(parameters: RsaJsonWebKeyParameters): KeyObject {
    const input: JsonWebKeyInput = { format: "jwk", key: parameters };
    return "d" in parameters ? createPrivateKey(input) : createPublicKey(input);
  }

  /**
   * Returns the Private Parameters of the JSON Web Key.
   *
   * @returns JSON Web Key Private Parameters.
   */
  public getPrivateParameters(): string[] {
    return this.#privateParameters;
  }

  /**
   * Validates the provided JSON Web Key Parameters.
   *
   * @param parameters JSON Web Key Parameters.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key Parameters is invalid.
   */
  public override validate(parameters: RsaJsonWebKeyParameters): void {
    if (!Strings.isNonEmpty(parameters.n) || Buffer.byteLength(parameters.n, "base64url") < 256) {
      throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "n".');
    }

    if (!Strings.isNonEmpty(parameters.e)) {
      throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "e".');
    }

    if (this.#privateParameters.some((parameter) => parameter in parameters)) {
      if (!Strings.isNonEmpty(parameters.d)) {
        throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "d".');
      }

      if (!Strings.isNonEmpty(parameters.p)) {
        throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "p".');
      }

      if (!Strings.isNonEmpty(parameters.q)) {
        throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "q".');
      }

      if (!Strings.isNonEmpty(parameters.dp)) {
        throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "dp".');
      }

      if (!Strings.isNonEmpty(parameters.dq)) {
        throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "dq".');
      }

      if (!Strings.isNonEmpty(parameters.qi)) {
        throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "qi".');
      }
    }

    super.validate(parameters);
  }
}
