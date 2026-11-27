import { jose } from "../../../jose/index.ts";
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
): Promise<JsonWebEncryptionHeader> {
  return await jose.header.create(JsonWebEncryptionHeader, parameters, additionalParameters);
}
