import { jose } from "../../../jose/index.ts";
import { JsonWebEncryptionHeader } from "../jsonwebencryption.header.js";
import type { JsonWebEncryptionHeaderParameters } from "../jsonwebencryption.header.parameters.ts";

/**
 * Parses the provided stringified JSON Web Encryption Header Parameters into a JSON Web Encryption Header.
 *
 * @param data Stringified JSON Web Encryption Header Parameters.
 * @param additionalParameters Optional additional JSON Web Encryption Header Parameters.
 * @returns JSON Web Encryption Header.
 * @throws {InvalidJoseHeaderError} The provided JSON Web Encryption Header Parameters is invalid.
 * @throws {TypeError} One of the provided arguments is invalid.
 */
export async function parse(
  data: string,
  additionalParameters?: Partial<JsonWebEncryptionHeaderParameters>,
): Promise<JsonWebEncryptionHeader> {
  return await jose.header.parse(JsonWebEncryptionHeader, data, additionalParameters);
}
