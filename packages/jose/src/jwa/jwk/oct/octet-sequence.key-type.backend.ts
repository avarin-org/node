import { Buffer } from "node:buffer";
import { createSecretKey, randomBytes } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { promisify } from "node:util";

import { Objects } from "@avarin/primitives/objects";
import { Strings } from "@avarin/primitives/strings";

import { InvalidJsonWebKeyError } from "../../../errors/invalid-jsonwebkey.error.ts";
import type { JsonWebKeyParameters } from "../../../jwk/jsonwebkey.parameters.ts";
import type { JsonWebKey } from "../../../jwk/jsonwebkey.ts";
import { KeyTypeBackend } from "../key-type.backend.ts";
import type { GenerateOctetSequenceJsonWebKeyOptions } from "./generate-octet-sequence-jsonwebkey.options.ts";
import type { OctetSequenceJsonWebKeyParameters } from "./octet-sequence.jsonwebkey.parameters.ts";

const randomBytesAsync = promisify(randomBytes);

/**
 * Implementation of the Octet Sequence Key Type Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.4|RFC 7518 Parameters for Symmetric Keys}
 */
export class OctetSequenceKeyTypeBackend extends KeyTypeBackend<OctetSequenceJsonWebKeyParameters> {
  /**
   * JSON Web Key Key Type.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.1|RFC 7517 "kty" (Key Type) Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.1|RFC 7518 "kty" (Key Type) Parameter Values}
   */
  public readonly name = "oct" as const;

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
    options: GenerateOctetSequenceJsonWebKeyOptions,
    parameters: Partial<JsonWebKeyParameters> = {},
  ): Promise<JsonWebKey<OctetSequenceJsonWebKeyParameters>> {
    if (!Objects.isPlain(options)) {
      throw new TypeError("The provided Octet Sequence JSON Web Key Generation Options is invalid.");
    }

    if (!("length" in options) || !Number.isSafeInteger(options.length) || options.length <= 0) {
      throw new TypeError('The provided Octet Sequence JSON Web Key Generation Option "length" is invalid.');
    }

    const secretKey = createSecretKey(await randomBytesAsync(options.length >>> 3));

    const jsonWebKeyParameters = {
      ...parameters,
      ...secretKey.export({ format: "jwk" }),
    } as OctetSequenceJsonWebKeyParameters;

    const { create } = await import("../../../jwk/create/create.ts");

    return await create(jsonWebKeyParameters);
  }

  /**
   * Creates a native Crypto Key.
   *
   * @param parameters JSON Web Key Parameters.
   * @returns Native Crypto Key.
   */
  public getCryptoKey(parameters: OctetSequenceJsonWebKeyParameters): KeyObject {
    return createSecretKey(parameters.k, "base64url");
  }

  /**
   * Returns the Private Parameters of the JSON Web Key.
   *
   * @returns JSON Web Key Private Parameters.
   */
  public getPrivateParameters(): string[] {
    return [];
  }

  /**
   * Validates the provided JSON Web Key Parameters.
   *
   * @param parameters JSON Web Key Parameters.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key Parameters is invalid.
   */
  public override validate(parameters: OctetSequenceJsonWebKeyParameters): void {
    if (!Strings.isNonEmpty(parameters.k) || Buffer.byteLength(parameters.k, "base64url") === 0) {
      throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "k".');
    }

    super.validate(parameters);
  }
}
