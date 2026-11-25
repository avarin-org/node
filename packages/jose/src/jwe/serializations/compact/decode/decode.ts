import { Buffer } from "node:buffer";

import { Strings } from "@avarin/primitives/strings";

import { InvalidJsonWebEncryptionError } from "../../../../errors/invalid-jsonwebencryption.error.ts";
import { header } from "../../../header/index.ts";
import type { CompactJsonWebEncryptionParameters } from "../compact.jsonwebencryption.parameters.ts";
import type { CompactJsonWebEncryptionToken } from "../compact.jsonwebencryption.token.ts";

/**
 * Decodes the provided Compact JSON Web Encryption Token into its Parameters.
 *
 * @param token Compact JSON Web Encryption Token.
 * @returns Compact JSON Web Encryption Parameters.
 * @throws {InvalidJsonWebEncryptionError} The provided JSON Web Encryption is invalid.
 */
export async function decode(token: string): Promise<CompactJsonWebEncryptionParameters> {
  if (!Strings.isNonEmpty(token)) {
    throw new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
  }

  const tokenParts = token.split(".") as CompactJsonWebEncryptionToken;

  if (tokenParts.length !== 5) {
    throw new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
  }

  try {
    const [
      encodedProtectedHeader,
      encodedEncryptedKey,
      encodedInitializationVector,
      encodedCiphertext,
      encodedAuthenticationTag,
    ] = tokenParts;

    const protectedHeader = await header.parse(Buffer.from(encodedProtectedHeader, "base64url").toString("utf8"));
    const encryptedKey = Buffer.from(encodedEncryptedKey, "base64url");
    const initializationVector = Buffer.from(encodedInitializationVector, "base64url");
    const ciphertext = Buffer.from(encodedCiphertext, "base64url");
    const authenticationTag = Buffer.from(encodedAuthenticationTag, "base64url");
    const additionalAuthenticatedData = Buffer.from(encodedProtectedHeader, "ascii");

    return {
      additionalAuthenticatedData,
      authenticationTag,
      ciphertext: ciphertext.byteLength > 0 ? ciphertext : null,
      encryptedKey,
      initializationVector,
      protectedHeader,
    };
  } catch (error: unknown) {
    throw new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.", { cause: error });
  }
}
