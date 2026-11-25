import { Buffer } from "node:buffer";

import { JSON } from "@avarin/primitives/json";
import { Objects } from "@avarin/primitives/objects";
import { Strings } from "@avarin/primitives/strings";

import { InvalidJsonWebEncryptionError } from "../../../../errors/invalid-jsonwebencryption.error.ts";
import { checkPartialJoseHeader } from "../../../../utils/check-partial-jose-header/check-partial-jose-header.ts";
import { header } from "../../../header/index.ts";
import type { JsonWebEncryptionHeaderParameters } from "../../../header/jsonwebencryption.header.parameters.ts";
import type { JsonWebEncryptionHeader } from "../../../header/jsonwebencryption.header.ts";
import type { FlattenedJsonWebEncryptionParameters } from "../flattened.jsonwebencryption.parameters.ts";
import type { FlattenedJsonWebEncryptionToken } from "../flattened.jsonwebencryption.token.ts";

function isValidFlattenedJsonWebEncryptionToken(token: FlattenedJsonWebEncryptionToken): boolean {
  try {
    if (!("protected" in token) && !("unprotected" in token) && !("header" in token)) {
      return false;
    }

    if (
      "protected" in token &&
      (!Strings.isNonEmpty(token.protected) ||
        !checkPartialJoseHeader(JSON.parse(Buffer.from(token.protected, "base64url").toString("utf8"))))
    ) {
      return false;
    }

    if ("unprotected" in token && (!Objects.isPlain(token.unprotected) || !checkPartialJoseHeader(token.unprotected))) {
      return false;
    }

    if ("header" in token && (!Objects.isPlain(token.header) || !checkPartialJoseHeader(token.header))) {
      return false;
    }

    if ("encrypted_key" in token && !Strings.isNonEmpty(token.encrypted_key)) {
      return false;
    }

    if ("aad" in token && !Strings.isNonEmpty(token.aad)) {
      return false;
    }

    if (!Strings.isNonEmpty(token.iv)) {
      return false;
    }

    if ("ciphertext" in token && !Strings.isNonEmpty(token.ciphertext)) {
      return false;
    }

    if (!Strings.isNonEmpty(token.tag)) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

async function getJoseHeader(
  protectedHeader: Partial<JsonWebEncryptionHeaderParameters> | null,
  unprotectedHeader: Partial<JsonWebEncryptionHeaderParameters> | null,
  recipientUnprotectedHeader: Partial<JsonWebEncryptionHeaderParameters> | null,
): Promise<JsonWebEncryptionHeader> {
  const headerKeys = [
    ...Object.keys(protectedHeader ?? {}),
    ...Object.keys(unprotectedHeader ?? {}),
    ...Object.keys(recipientUnprotectedHeader ?? {}),
  ];

  if (headerKeys.length !== new Set(headerKeys).size) {
    throw new TypeError("Cannot have repeated JSON Web Encryption Header Parameters.");
  }

  const headerParameters = {
    ...protectedHeader,
    ...unprotectedHeader,
    ...recipientUnprotectedHeader,
  } as JsonWebEncryptionHeaderParameters;

  return await header.create(headerParameters);
}

/**
 * Decodes the provided Flattened JSON Web Encryption Token into its Parameters.
 *
 * @param token Flattened JSON Web Encryption Token.
 * @returns Flattened JSON Web Encryption Parameters.
 * @throws {InvalidJsonWebEncryptionError} The provided JSON Web Encryption is invalid.
 */
export async function decode(token: FlattenedJsonWebEncryptionToken): Promise<FlattenedJsonWebEncryptionParameters> {
  if (!Objects.isPlain(token) || !isValidFlattenedJsonWebEncryptionToken(token)) {
    throw new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
  }

  try {
    let protectedHeader: Partial<JsonWebEncryptionHeaderParameters> | null = null;
    let unprotectedHeader: Partial<JsonWebEncryptionHeaderParameters> | null = null;
    let recipientUnprotectedHeader: Partial<JsonWebEncryptionHeaderParameters> | null = null;

    if ("protected" in token) {
      protectedHeader = JSON.parse(Buffer.from(token.protected, "base64url").toString("utf8"));
    }

    if ("unprotected" in token) {
      unprotectedHeader = token.unprotected;
    }

    if ("header" in token) {
      recipientUnprotectedHeader = token.header;
    }

    const joseHeader = await getJoseHeader(protectedHeader, unprotectedHeader, recipientUnprotectedHeader);

    return {
      additionalAuthenticatedData:
        "aad" in token && token.aad.includes(".")
          ? Buffer.from(token.aad.substring(token.aad.indexOf(".") + 1), "base64url")
          : null,
      authenticationTag: Buffer.from(token.tag, "base64url"),
      ciphertext: "ciphertext" in token ? Buffer.from(token.ciphertext, "base64url") : null,
      encryptedKey: "encrypted_key" in token ? Buffer.from(token.encrypted_key, "base64url") : null,
      header: joseHeader,
      initializationVector: Buffer.from(token.iv, "base64url"),
      protectedHeader,
      recipientUnprotectedHeader,
      unprotectedHeader,
    };
  } catch (error: unknown) {
    throw new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.", { cause: error });
  }
}
