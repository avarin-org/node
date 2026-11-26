import { Functions } from "@avarin/primitives/functions";
import { Objects } from "@avarin/primitives/objects";
import type { Constructor } from "@avarin/primitives/types";

import { InvalidJoseHeaderError } from "../../../errors/invalid-jose-header.error.ts";
import { getJsonWebKeyFromJoseHeader } from "../../../utils/get-jsonwebkey-from-jose-header/get-jsonwebkey-from-jose-header.ts";
import { getX509CertificateChain } from "../../../utils/get-x509-certificate-chain/get-x509-certificate-chain.ts";
import { validateJsonWebKeyAndX509CertificateChain } from "../../../utils/validate-jsonwebkey-and-x509-certificate-chain/validate-jsonwebkey-and-x509-certificate-chain.ts";
import type { JsonWebEncryptionHeaderParameters } from "../jsonwebencryption.header.parameters.ts";
import { JsonWebEncryptionHeader } from "../jsonwebencryption.header.ts";

/**
 * Creates a JSON Web Encryption Header based on the provided JSON Web Encryption Header Parameters.
 *
 * @param parameters JSON Web Encryption Header Parameters.
 * @param additionalParameters Optional additional JSON Web Encryption Header Parameters.
 * @returns JSON Web Encryption Header.
 * @throws {InvalidJoseHeaderError} The provided JSON Web Encryption Header Parameters is invalid.
 * @throws {TypeError} One of the provided arguments is invalid.
 */
export async function create(
  parameters: JsonWebEncryptionHeaderParameters,
  additionalParameters?: Partial<JsonWebEncryptionHeaderParameters>,
): Promise<JsonWebEncryptionHeader>;

/**
 * Creates a JSON Web Encryption Header based on the provided JSON Web Encryption Header Parameters.
 *
 * @param HeaderConstructor JSON Web Encryption Header Constructor.
 * @param parameters JSON Web Encryption Header Parameters.
 * @param additionalParameters Optional additional JSON Web Encryption Header Parameters.
 * @returns JSON Web Encryption Header.
 * @throws {InvalidJoseHeaderError} The provided JSON Web Encryption Header Parameters is invalid.
 * @throws {TypeError} One of the provided arguments is invalid.
 */
export async function create<T extends JsonWebEncryptionHeader>(
  HeaderConstructor: Constructor<T>,
  parameters: JsonWebEncryptionHeaderParameters,
  additionalParameters?: Partial<JsonWebEncryptionHeaderParameters>,
): Promise<T>;

/**
 * Creates a JSON Web Encryption Header based on the provided JSON Web Encryption Header Parameters.
 *
 * @param parametersOrHeaderConstructor JSON Web Encryption Header Parameters or JSON Web Encryption Header Constructor.
 * @param parametersOrAdditionalParameters JSON Web Encryption Header Parameters or Optional additional JSON Web
 *   Encryption Header Parameters.
 * @param additionalParameters Optional additional JSON Web Encryption Header Parameters.
 * @returns JSON Web Encryption Header.
 * @throws {InvalidJoseHeaderError} The provided JSON Web Encryption Header Parameters is invalid.
 * @throws {TypeError} One of the provided arguments is invalid.
 */
export async function create<T extends JsonWebEncryptionHeader = JsonWebEncryptionHeader>(
  parametersOrHeaderConstructor: JsonWebEncryptionHeaderParameters | Constructor<T>,
  parametersOrAdditionalParameters?: JsonWebEncryptionHeaderParameters | Partial<JsonWebEncryptionHeaderParameters>,
  additionalParameters: Partial<JsonWebEncryptionHeaderParameters> = {},
): Promise<T> {
  const HeaderConstructor = Functions.isClass(parametersOrHeaderConstructor)
    ? parametersOrHeaderConstructor
    : JsonWebEncryptionHeader;

  const parameters = Functions.isClass(parametersOrHeaderConstructor)
    ? parametersOrAdditionalParameters!
    : parametersOrHeaderConstructor;

  if (arguments.length === 2 && !Functions.isClass(parametersOrHeaderConstructor)) {
    additionalParameters = parametersOrAdditionalParameters!;
  }

  if (
    HeaderConstructor !== JsonWebEncryptionHeader &&
    !(HeaderConstructor.prototype instanceof JsonWebEncryptionHeader)
  ) {
    throw new TypeError("The provided JSON Web Encryption Header Constructor is invalid.");
  }

  if (!Objects.isPlain(parameters)) {
    throw new InvalidJoseHeaderError("The provided JSON Web Encryption Header Parameters is invalid.");
  }

  if (!Objects.isPlain(additionalParameters)) {
    throw new InvalidJoseHeaderError("The provided JSON Web Encryption Header Parameters is invalid.");
  }

  const jsonWebEncryptionHeaderParameters = {
    ...parameters,
    ...additionalParameters,
  } as JsonWebEncryptionHeaderParameters;

  const header = new HeaderConstructor(jsonWebEncryptionHeaderParameters);

  const jsonWebKey = await getJsonWebKeyFromJoseHeader(jsonWebEncryptionHeaderParameters);
  const certificateChain = await getX509CertificateChain(jsonWebEncryptionHeaderParameters);

  if (jsonWebKey !== null && certificateChain !== null) {
    validateJsonWebKeyAndX509CertificateChain(jsonWebKey.parameters, certificateChain);
  }

  header.jsonWebKey = jsonWebKey;
  header.certificateChain = certificateChain;

  return header as T;
}
