import { Functions } from "@avarin/primitives/functions";
import { Strings } from "@avarin/primitives/strings";

import type { EllipticCurveJsonWebKeyParameters } from "../../jwa/jwk/ec/elliptic-curve.jsonwebkey.parameters.ts";
import type { GenerateEllipticCurveJsonWebKeyOptions } from "../../jwa/jwk/ec/generate-elliptic-curve-jsonwebkey.options.ts";
import { JSONWEBKEY_BACKEND_REGISTRY } from "../../jwa/jwk/jsonwebkey.backend.registry.ts";
import type { KeyType } from "../../jwa/jwk/key-type.type.ts";
import type { GenerateOctetSequenceJsonWebKeyOptions } from "../../jwa/jwk/oct/generate-octet-sequence-jsonwebkey.options.ts";
import type { OctetSequenceJsonWebKeyParameters } from "../../jwa/jwk/oct/octet-sequence.jsonwebkey.parameters.ts";
import type { GenerateRsaJsonWebKeyOptions } from "../../jwa/jwk/rsa/generate-rsa-jsonwebkey.options.ts";
import type { RsaJsonWebKeyParameters } from "../../jwa/jwk/rsa/rsa.jsonwebkey.parameters.ts";
import type { JsonWebKeyParameters } from "../jsonwebkey.parameters.ts";
import type { JsonWebKey } from "../jsonwebkey.ts";

/**
 * Generates an Elliptic Curve JSON Web Key based on the provided options.
 *
 * @param keyType JSON Web Key Key Type.
 * @param options Elliptic Curve JSON Web Key Generation Options.
 * @param parameters Optional additional JSON Web Key Parameters.
 * @returns Generated Elliptic Curve JSON Web Key.
 * @throws {InvalidJsonWebKeyError} The provided additional JSON Web Key Parameters is invalid.
 * @throws {TypeError} One of the provided arguments is invalid.
 */
export async function generate(
  keyType: "EC",
  options: GenerateEllipticCurveJsonWebKeyOptions,
  parameters?: Partial<JsonWebKeyParameters>,
): Promise<JsonWebKey<EllipticCurveJsonWebKeyParameters>>;

/**
 * Generates an RSA JSON Web Key based on the provided options.
 *
 * @param keyType JSON Web Key Key Type.
 * @param options RSA JSON Web Key Generation Options.
 * @param parameters Optional additional JSON Web Key Parameters.
 * @returns Generated RSA JSON Web Key.
 * @throws {InvalidJsonWebKeyError} The provided additional JSON Web Key Parameters is invalid.
 * @throws {TypeError} One of the provided arguments is invalid.
 */
export async function generate(
  keyType: "RSA",
  options: GenerateRsaJsonWebKeyOptions,
  parameters?: Partial<JsonWebKeyParameters>,
): Promise<JsonWebKey<RsaJsonWebKeyParameters>>;

/**
 * Generates an Octet Sequence JSON Web Key based on the provided options.
 *
 * @param keyType JSON Web Key Key Type.
 * @param options Octet Sequence JSON Web Key Generation Options.
 * @param parameters Optional additional JSON Web Key Parameters.
 * @returns Generated Octet Sequence JSON Web Key.
 * @throws {InvalidJsonWebKeyError} The provided additional JSON Web Key Parameters is invalid.
 * @throws {TypeError} One of the provided arguments is invalid.
 */
export async function generate(
  keyType: "oct",
  options: GenerateOctetSequenceJsonWebKeyOptions,
  parameters?: Partial<JsonWebKeyParameters>,
): Promise<JsonWebKey<OctetSequenceJsonWebKeyParameters>>;

/**
 * Generates a JSON Web Key based on the provided options.
 *
 * @param keyType JSON Web Key Key Type.
 * @param options JSON Web Key Generation Options.
 * @param parameters Optional additional JSON Web Key Parameters.
 * @returns Generated JSON Web Key.
 * @throws {InvalidJsonWebKeyError} The provided additional JSON Web Key Parameters is invalid.
 * @throws {TypeError} One of the provided arguments is invalid.
 */
export async function generate(
  keyType: KeyType,
  options: NodeJS.Dict<unknown>,
  parameters?: Partial<JsonWebKeyParameters>,
): Promise<JsonWebKey>;

/**
 * Generates a JSON Web Key based on the provided options.
 *
 * @param keyType JSON Web Key Key Type.
 * @param options JSON Web Key Generation Options.
 * @param parameters Optional additional JSON Web Key Parameters.
 * @returns Generated JSON Web Key.
 * @throws {InvalidJsonWebKeyError} The provided additional JSON Web Key Parameters is invalid.
 * @throws {TypeError} One of the provided arguments is invalid.
 */
export async function generate(
  keyType: KeyType,
  options: NodeJS.Dict<unknown>,
  parameters: Partial<JsonWebKeyParameters> = {},
): Promise<JsonWebKey> {
  if (!Strings.isNonEmpty(keyType)) {
    throw new TypeError("The provided JSON Web Key Key Type is invalid.");
  }

  const Constructor = JSONWEBKEY_BACKEND_REGISTRY.find((backend) => backend.keyType === keyType);

  if (!Functions.isClass(Constructor)) {
    throw new TypeError("The provided JSON Web Key Key Type is invalid.");
  }

  return await Constructor.generate(options, parameters);
}
