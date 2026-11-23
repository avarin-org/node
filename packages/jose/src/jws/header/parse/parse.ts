import { JSON } from "@avarin/primitives/json";

import { InvalidJoseHeaderError } from "../../../errors/invalid-jose-header.error.ts";
import { create } from "../create/create.ts";
import type { JsonWebSignatureHeaderParameters } from "../jsonwebsignature.header.parameters.ts";
import type { JsonWebSignatureHeader } from "../jsonwebsignature.header.ts";

/**
 * Parses the provided stringified JSON Web Signature Header Parameters into a JSON Web Signature Header.
 *
 * @param data Stringified JSON Web Signature Header Parameters.
 * @param additionalParameters Optional additional JSON Web Signature Header Parameters.
 * @returns Parsed JSON Web Signature Header.
 * @throws {InvalidJoseHeaderError} The provided JSON Web Signature Header Parameters is invalid.
 */
export async function parse(
  data: string,
  additionalParameters: Partial<JsonWebSignatureHeaderParameters> = {},
): Promise<JsonWebSignatureHeader> {
  try {
    return await create(JSON.parse(data), additionalParameters);
  } catch (error: unknown) {
    throw new InvalidJoseHeaderError("The provided JSON Web Signature Header Parameters is invalid.", { cause: error });
  }
}
