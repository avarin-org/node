import { Buffer } from "node:buffer";

import { JSON } from "@avarin/primitives/json";
import { Strings } from "@avarin/primitives/strings";

import { InvalidJsonWebEncryptionError } from "../../../../errors/invalid-jsonwebencryption.error.ts";
import type { JsonWebEncryptionHeaderParameters } from "../../../header/jsonwebencryption.header.parameters.ts";
import type { CompactJsonWebEncryptionParameters } from "../compact.jsonwebencryption.parameters.ts";
import type { CompactJsonWebEncryptionToken } from "../compact.jsonwebencryption.token.ts";

/**
 * Decodes the provided Compact JSON Web Encryption Token into its Parameters.
 *
 * @param token Compact JSON Web Encryption Token.
 * @returns Compact JSON Web Encryption Parameters.
 * @throws {InvalidJsonWebEncryptionError} The provided JSON Web Encryption is invalid.
 */
export function decode(token: string): CompactJsonWebEncryptionParameters {
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

    const joseHeader = JSON.parse<JsonWebEncryptionHeaderParameters>(
      Buffer.from(encodedProtectedHeader, "base64url").toString("utf8"),
    );

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
      joseHeader,
    };
  } catch (error: unknown) {
    throw new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.", { cause: error });
  }
}
