import { JSON } from "@avarin/primitives/json";

import { InvalidJoseHeaderError } from "../../../errors/invalid-jose-header.error.ts";
import { create } from "../create/create.ts";
import type { JsonWebEncryptionHeaderParameters } from "../jsonwebencryption.header.parameters.ts";
import type { JsonWebEncryptionHeader } from "../jsonwebencryption.header.ts";

/**
 * Parses the provided stringified JSON Web Encryption Header Parameters into a JSON Web Encryption Header.
 *
 * @param data Stringified JSON Web Encryption Header Parameters.
 * @param additionalParameters Optional additional JSON Web Encryption Header Parameters.
 * @returns Parsed JSON Web Encryption Header.
 * @throws {InvalidJoseHeaderError} The provided JSON Web Encryption Header Parameters is invalid.
 */
export async function parse(
  data: string,
  additionalParameters: Partial<JsonWebEncryptionHeaderParameters> = {},
): Promise<JsonWebEncryptionHeader> {
  try {
    return await create(JSON.parse(data), additionalParameters);
  } catch (error: unknown) {
    throw new InvalidJoseHeaderError("The provided JSON Web Encryption Header Parameters is invalid.", {
      cause: error,
    });
  }
}
