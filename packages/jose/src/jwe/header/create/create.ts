import { Objects } from "@avarin/primitives/objects";

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
 * @param additionalParameters Optional additional JSON Web Encryption Parameters.
 * @returns JSON Web Encryption Header.
 * @throws {InvalidJoseHeaderError} The provided JSON Web Encryption Header Parameters is invalid.
 */
export async function create(
  parameters: JsonWebEncryptionHeaderParameters,
  additionalParameters: Partial<JsonWebEncryptionHeaderParameters> = {},
): Promise<JsonWebEncryptionHeader> {
  if (!Objects.isPlain(parameters)) {
    throw new InvalidJoseHeaderError("The provided JSON Web Encryption Header Parameters is invalid.");
  }

  if (!Objects.isPlain(additionalParameters)) {
    throw new InvalidJoseHeaderError("The provided JSON Web Encryption Header Parameters is invalid.");
  }

  const jsonWebEncryptionHeaderParameters: JsonWebEncryptionHeaderParameters = {
    ...parameters,
    ...additionalParameters,
  };

  const header = new JsonWebEncryptionHeader(jsonWebEncryptionHeaderParameters);

  const jsonWebKey = await getJsonWebKeyFromJoseHeader(jsonWebEncryptionHeaderParameters);
  const certificateChain = await getX509CertificateChain(jsonWebEncryptionHeaderParameters);

  if (jsonWebKey !== null && certificateChain !== null) {
    validateJsonWebKeyAndX509CertificateChain(jsonWebKey.parameters, certificateChain);
  }

  header.jsonWebKey = jsonWebKey;
  header.certificateChain = certificateChain;

  return header;
}
