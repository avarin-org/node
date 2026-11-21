import { Objects } from "@avarin/primitives/objects";

import { InvalidJsonWebKeyError } from "../../errors/invalid-jsonwebkey.error.ts";
import { getX509CertificateChain } from "../../utils/get-x509-certificate-chain/get-x509-certificate-chain.ts";
import { validateJsonWebKeyAndX509CertificateChain } from "../../utils/validate-jsonwebkey-and-x509-certificate-chain/validate-jsonwebkey-and-x509-certificate-chain.ts";
import type { JsonWebKeyParameters } from "../jsonwebkey.parameters.ts";
import { JsonWebKey } from "../jsonwebkey.ts";

/**
 * Creates a JSON Web Key based on the provided Parameters.
 *
 * @param parameters JSON Web Key Parameters.
 * @param additionalParameters Optional additional JSON Web Key Parameters.
 * @returns JSON Web Key.
 * @throws {InvalidJsonWebKeyError} The provided JSON Web Key Parameters are invalid.
 */
export async function create<T extends JsonWebKeyParameters = JsonWebKeyParameters>(
  parameters: T,
  additionalParameters: Partial<JsonWebKeyParameters> = {},
): Promise<JsonWebKey<T>> {
  if (!Objects.isPlain(parameters)) {
    throw new InvalidJsonWebKeyError("The provided JSON Web Key Parameters is invalid.");
  }

  if (!Objects.isPlain(additionalParameters)) {
    throw new InvalidJsonWebKeyError("The provided JSON Web Key Parameters is invalid.");
  }

  const jsonWebKeyParameters: T = { ...parameters, ...additionalParameters };

  const jsonWebKey = new JsonWebKey(jsonWebKeyParameters);
  const certificateChain = await getX509CertificateChain(jsonWebKeyParameters);

  if (certificateChain !== null) {
    validateJsonWebKeyAndX509CertificateChain(jsonWebKeyParameters, certificateChain);
  }

  jsonWebKey.certificateChain = certificateChain;

  return jsonWebKey;
}
