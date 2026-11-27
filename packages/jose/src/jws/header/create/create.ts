import { jose } from "../../../jose/index.ts";
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
): Promise<JsonWebSignatureHeader> {
  return await jose.header.create(JsonWebSignatureHeader, parameters, additionalParameters);
}
