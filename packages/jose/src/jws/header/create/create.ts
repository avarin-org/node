import { Objects } from "@avarin/primitives/objects";

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
 * @param additionalParameters Optional additional JSON Web Signature Parameters.
 * @returns JSON Web Signature Header.
 * @throws {InvalidJoseHeaderError} The provided JSON Web Signature Header Parameters is invalid.
 */
export async function create(
  parameters: JsonWebSignatureHeaderParameters,
  additionalParameters: Partial<JsonWebSignatureHeaderParameters> = {},
): Promise<JsonWebSignatureHeader> {
  if (!Objects.isPlain(parameters)) {
    throw new InvalidJoseHeaderError("The provided JSON Web Signature Header Parameters is invalid.");
  }

  if (!Objects.isPlain(additionalParameters)) {
    throw new InvalidJoseHeaderError("The provided JSON Web Signature Header Parameters is invalid.");
  }

  const jsonWebSignatureHeaderParameters: JsonWebSignatureHeaderParameters = { ...parameters, ...additionalParameters };

  const header = new JsonWebSignatureHeader(jsonWebSignatureHeaderParameters);

  const jsonWebKey = await getJsonWebKeyFromJoseHeader(jsonWebSignatureHeaderParameters);
  const certificateChain = await getX509CertificateChain(jsonWebSignatureHeaderParameters);

  if (jsonWebKey !== null && certificateChain !== null) {
    validateJsonWebKeyAndX509CertificateChain(jsonWebKey.parameters, certificateChain);
  }

  header.jsonWebKey = jsonWebKey;
  header.certificateChain = certificateChain;

  return header;
}
