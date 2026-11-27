import { jose } from "../../../jose/index.ts";
import { JsonWebSignatureHeader } from "../jsonwebsignature.header.js";
import type { JsonWebSignatureHeaderParameters } from "../jsonwebsignature.header.parameters.ts";

/**
 * Parses the provided stringified JSON Web Signature Header Parameters into a JSON Web Signature Header.
 *
 * @param data Stringified JSON Web Signature Header Parameters.
 * @param additionalParameters Optional additional JSON Web Signature Header Parameters.
 * @returns JSON Web Signature Header.
 * @throws {InvalidJoseHeaderError} The provided JSON Web Signature Header Parameters is invalid.
 * @throws {TypeError} One of the provided arguments is invalid.
 */
export async function parse(
  data: string,
  additionalParameters?: Partial<JsonWebSignatureHeaderParameters>,
): Promise<JsonWebSignatureHeader> {
  return await jose.header.parse(JsonWebSignatureHeader, data, additionalParameters);
}
