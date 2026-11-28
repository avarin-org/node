import { Buffer } from "node:buffer";

import { Strings } from "@avarin/primitives/strings";

import { InvalidJsonWebEncryptionError } from "../../../../errors/invalid-jsonwebencryption.error.ts";
import { InvalidJsonWebTokenError } from "../../../../errors/invalid-jsonwebtoken.error.ts";
import { jwe } from "../../../../jwe/index.ts";
import type { EncryptedJsonWebTokenParameters } from "../encrypted.jsonwebtoken.parameters.ts";

/**
 * Decodes the provided Encrypted JSON Web Token into its Parameters.
 *
 * @param token Encrypted JSON Web Token.
 * @param options JSON Web Token Claims Options.
 * @returns Encrypted JSON Web Token Parameters.
 * @throws {InvalidJsonWebTokenError} The provided JSON Web Token is invalid.
 */
export function decode(token: string): EncryptedJsonWebTokenParameters {
  if (!Strings.isNonEmpty(token)) {
    throw new InvalidJsonWebTokenError("The provided JSON Web Token is invalid.");
  }

  try {
    const {
      additionalAuthenticatedData,
      authenticationTag,
      ciphertext,
      encryptedKey,
      initializationVector,
      joseHeader,
    } = jwe.compact.decode(token);

    if (!Buffer.isBuffer(ciphertext)) {
      throw new InvalidJsonWebEncryptionError("The provided Encrypted JSON Web Token has an empty Ciphertext.");
    }

    return {
      additionalAuthenticatedData,
      authenticationTag,
      ciphertext,
      encryptedKey,
      initializationVector,
      joseHeader,
    };
  } catch (error: unknown) {
    throw new InvalidJsonWebTokenError("The provided JSON Web Token is invalid.", { cause: error });
  }
}
