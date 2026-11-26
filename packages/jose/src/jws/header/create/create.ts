import { Functions } from "@avarin/primitives/functions";
import { Objects } from "@avarin/primitives/objects";
import type { Constructor } from "@avarin/primitives/types";

import { InvalidJoseHeaderError } from "../../../errors/invalid-jose-header.error.ts";
import { getJsonWebKeyFromJoseHeader } from "../../../utils/get-jsonwebkey-from-jose-header/get-jsonwebkey-from-jose-header.ts";
import { getX509CertificateChain } from "../../../utils/get-x509-certificate-chain/get-x509-certificate-chain.ts";
import { validateJsonWebKeyAndX509CertificateChain } from "../../../utils/validate-jsonwebkey-and-x509-certificate-chain/validate-jsonwebkey-and-x509-certificate-chain.ts";
import type { JsonWebSignatureHeaderParameters } from "../jsonwebsignature.header.parameters.ts";
import { JsonWebSignatureHeader } from "../jsonwebsignature.header.ts";

/**
 * Creates a JSON Web Signature Header based on the provided JSON Web Signature Header Parameters.
 *
 * @param parameters JSON Web Signature Header Parameters.
 * @param additionalParameters Optional additional JSON Web Signature Header Parameters.
 * @returns JSON Web Signature Header.
 * @throws {InvalidJoseHeaderError} The provided JSON Web Signature Header Parameters is invalid.
 * @throws {TypeError} One of the provided arguments is invalid.
 */
export async function create(
  parameters: JsonWebSignatureHeaderParameters,
  additionalParameters?: Partial<JsonWebSignatureHeaderParameters>,
): Promise<JsonWebSignatureHeader>;

/**
 * Creates a JSON Web Signature Header based on the provided JSON Web Signature Header Parameters.
 *
 * @param HeaderConstructor JSON Web Signature Header Constructor.
 * @param parameters JSON Web Signature Header Parameters.
 * @param additionalParameters Optional additional JSON Web Signature Header Parameters.
 * @returns JSON Web Signature Header.
 * @throws {InvalidJoseHeaderError} The provided JSON Web Signature Header Parameters is invalid.
 * @throws {TypeError} One of the provided arguments is invalid.
 */
export async function create<T extends JsonWebSignatureHeader>(
  HeaderConstructor: Constructor<T>,
  parameters: JsonWebSignatureHeaderParameters,
  additionalParameters?: Partial<JsonWebSignatureHeaderParameters>,
): Promise<T>;

/**
 * Creates a JSON Web Signature Header based on the provided JSON Web Signature Header Parameters.
 *
 * @param parametersOrHeaderConstructor JSON Web Signature Header Parameters or JSON Web Signature Header Constructor.
 * @param parametersOrAdditionalParameters JSON Web Signature Header Parameters or Optional additional JSON Web
 *   Signature Header Parameters.
 * @param additionalParameters Optional additional JSON Web Signature Header Parameters.
 * @returns JSON Web Signature Header.
 * @throws {InvalidJoseHeaderError} The provided JSON Web Signature Header Parameters is invalid.
 * @throws {TypeError} One of the provided arguments is invalid.
 */
export async function create<T extends JsonWebSignatureHeader = JsonWebSignatureHeader>(
  parametersOrHeaderConstructor: JsonWebSignatureHeaderParameters | Constructor<T>,
  parametersOrAdditionalParameters?: JsonWebSignatureHeaderParameters | Partial<JsonWebSignatureHeaderParameters>,
  additionalParameters: Partial<JsonWebSignatureHeaderParameters> = {},
): Promise<T> {
  const HeaderConstructor = Functions.isClass(parametersOrHeaderConstructor)
    ? parametersOrHeaderConstructor
    : JsonWebSignatureHeader;

  const parameters = Functions.isClass(parametersOrHeaderConstructor)
    ? parametersOrAdditionalParameters!
    : parametersOrHeaderConstructor;

  if (arguments.length === 2 && !Functions.isClass(parametersOrHeaderConstructor)) {
    additionalParameters = parametersOrAdditionalParameters!;
  }

  if (
    HeaderConstructor !== JsonWebSignatureHeader &&
    !(HeaderConstructor.prototype instanceof JsonWebSignatureHeader)
  ) {
    throw new TypeError("The provided JSON Web Signature Header Constructor is invalid.");
  }

  if (!Objects.isPlain(parameters)) {
    throw new InvalidJoseHeaderError("The provided JSON Web Signature Header Parameters is invalid.");
  }

  if (!Objects.isPlain(additionalParameters)) {
    throw new InvalidJoseHeaderError("The provided JSON Web Signature Header Parameters is invalid.");
  }

  const jsonWebSignatureHeaderParameters = {
    ...parameters,
    ...additionalParameters,
  } as JsonWebSignatureHeaderParameters;

  const header = new HeaderConstructor(jsonWebSignatureHeaderParameters);

  const jsonWebKey = await getJsonWebKeyFromJoseHeader(jsonWebSignatureHeaderParameters);
  const certificateChain = await getX509CertificateChain(jsonWebSignatureHeaderParameters);

  if (jsonWebKey !== null && certificateChain !== null) {
    validateJsonWebKeyAndX509CertificateChain(jsonWebKey.parameters, certificateChain);
  }

  header.jsonWebKey = jsonWebKey;
  header.certificateChain = certificateChain;

  return header as T;
}
