import { Functions } from "@avarin/primitives/functions";
import { Objects } from "@avarin/primitives/objects";
import type { Constructor } from "@avarin/primitives/types";

import { InvalidJoseHeaderError } from "../../../errors/invalid-jose-header.error.ts";
import { jwk } from "../../../jwk/index.ts";
import type { JsonWebKey } from "../../../jwk/jsonwebkey.ts";
import { jwks } from "../../../jwks/index.ts";
import type { JsonWebKeySet } from "../../../jwks/jsonwebkeyset.ts";
import { getX509CertificateChain } from "../../../utils/get-x509-certificate-chain/get-x509-certificate-chain.ts";
import { validateJsonWebKeyAndX509CertificateChain } from "../../../utils/validate-jsonwebkey-and-x509-certificate-chain/validate-jsonwebkey-and-x509-certificate-chain.ts";
import type { JoseHeaderParameters } from "../jose.header.parameters.ts";
import { JoseHeader } from "../jose.header.ts";

/**
 * Fetches a JSON Web Key Set from the provided URL.
 *
 * @param url JSON Web Key Set URL.
 * @returns JSON Web Key Set.
 * @throws {Error} Failed to parse a JSON Web Key Set from the provided URL.
 */
export async function getJsonWebKeySetFromUrl(url: string): Promise<JsonWebKeySet> {
  const response = await globalThis.fetch(url);

  if (!response.ok) {
    throw new Error("Failed to parse a JSON Web Key Set from the provided URL.");
  }

  const stringifiedJsonWebKeySet = await response.text();

  return await jwks.parse(stringifiedJsonWebKeySet);
}

/**
 * Gets a JSON Web Key from the provided JOSE Header Parameters.
 *
 * @param parameters JOSE Header Parameters.
 * @returns JSON Web Key from the provided JOSE Header Parameters.
 * @throws {InvalidJoseHeaderError} The provided JOSE Header Parameters is invalid.
 */
export async function getJsonWebKeyFromJoseHeader(parameters: JoseHeaderParameters): Promise<JsonWebKey | null> {
  if (!("jku" in parameters) && !("jwk" in parameters)) {
    return null;
  }

  let jsonWebKey!: JsonWebKey;

  if ("jku" in parameters) {
    try {
      const jsonWebKeySet = await getJsonWebKeySetFromUrl(parameters.jku);
      jsonWebKey = jsonWebKeySet.get((key) => key.kid === parameters.kid);
    } catch (error: unknown) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "jku".', { cause: error });
    }
  }

  if ("jwk" in parameters) {
    if ("kid" in parameters && parameters.kid !== parameters.jwk.kid) {
      throw new InvalidJoseHeaderError('Mismatching JOSE Header and JSON Web Key Parameters "kid".');
    }

    try {
      jsonWebKey = await jwk.create(parameters.jwk);
    } catch (error: unknown) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "jwk".', { cause: error });
    }
  }

  if ("alg" in jsonWebKey.parameters && jsonWebKey.parameters.alg !== parameters.alg) {
    throw new InvalidJoseHeaderError('Mismatching JOSE Header and JSON Web Key Parameters "alg".');
  }

  return jsonWebKey;
}

/**
 * Creates a JOSE Header based on the provided JOSE Header Parameters.
 *
 * @param HeaderConstructor JOSE Header Constructor.
 * @param parameters JOSE Header Parameters.
 * @param additionalParameters Optional additional JOSE Header Parameters.
 * @returns JOSE Header.
 * @throws {InvalidJoseHeaderError} The provided JOSE Header Parameters is invalid.
 * @throws {TypeError} One of the provided arguments is invalid.
 */
export async function create<T extends JoseHeader>(
  HeaderConstructor: Constructor<T>,
  parameters: JoseHeaderParameters,
  additionalParameters: Partial<JoseHeaderParameters> = {},
): Promise<T> {
  if (!Functions.isClass(HeaderConstructor) || !(HeaderConstructor.prototype instanceof JoseHeader)) {
    throw new TypeError("The provided JOSE Header Constructor is invalid.");
  }

  if (!Objects.isPlain(parameters)) {
    throw new TypeError("The provided JOSE Header Parameters is invalid.");
  }

  if (!Objects.isPlain(additionalParameters)) {
    throw new TypeError("The provided JOSE Header Parameters is invalid.");
  }

  const joseHeaderParameters: JoseHeaderParameters = { ...parameters, ...additionalParameters };

  const header = new HeaderConstructor(joseHeaderParameters);

  try {
    const jsonWebKey = await getJsonWebKeyFromJoseHeader(joseHeaderParameters);
    const certificateChain = await getX509CertificateChain(joseHeaderParameters);

    if (jsonWebKey !== null && certificateChain !== null) {
      validateJsonWebKeyAndX509CertificateChain(jsonWebKey.parameters, certificateChain);
    }

    header.jsonWebKey = jsonWebKey;
    header.certificateChain = certificateChain;

    return header;
  } catch (error: unknown) {
    throw error instanceof InvalidJoseHeaderError
      ? error
      : new InvalidJoseHeaderError("The provided JOSE Header Parameters is invalid.", { cause: error });
  }
}
