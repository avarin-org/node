import { Buffer } from "node:buffer";

import { JSON } from "@avarin/primitives/json";
import { Objects } from "@avarin/primitives/objects";
import { Strings } from "@avarin/primitives/strings";

import { InvalidJsonWebEncryptionError } from "../../../../errors/invalid-jsonwebencryption.error.ts";
import { checkPartialJoseHeader } from "../../../../utils/check-partial-jose-header/check-partial-jose-header.ts";
import type { JsonWebEncryptionHeaderParameters } from "../../../header/jsonwebencryption.header.parameters.ts";
import type {
  GeneralJsonWebEncryptionParameters,
  GeneralJsonWebEncryptionParametersRecipient,
} from "../general.jsonwebencryption.parameters.ts";
import type { GeneralJsonWebEncryptionToken } from "../general.jsonwebencryption.token.ts";

function isValidGeneralJsonWebEncryptionToken(token: GeneralJsonWebEncryptionToken): boolean {
  if (!Strings.isNonEmpty(token.iv)) {
    return false;
  }

  if ("aad" in token && !Strings.isNonEmpty(token.aad)) {
    return false;
  }

  if ("ciphertext" in token && !Strings.isNonEmpty(token.ciphertext)) {
    return false;
  }

  if (!Strings.isNonEmpty(token.tag)) {
    return false;
  }

  if ("protected" in token && !Strings.isNonEmpty(token.protected)) {
    return false;
  }

  if ("unprotected" in token && !checkPartialJoseHeader(token.unprotected)) {
    return false;
  }

  if (
    !Array.isArray(token.recipients) ||
    token.recipients.length === 0 ||
    token.recipients.some((recipient) => !Objects.isPlain(recipient))
  ) {
    return false;
  }

  for (const recipient of token.recipients) {
    if (!("protected" in token) && !("unprotected" in token) && !("header" in recipient)) {
      return false;
    }

    if ("header" in recipient && !checkPartialJoseHeader(recipient.header)) {
      return false;
    }

    if (!Strings.isNonEmpty(recipient.encrypted_key)) {
      return false;
    }
  }

  return true;
}

function getJoseHeaderParameters(
  protectedHeader: Partial<JsonWebEncryptionHeaderParameters> | null | undefined,
  unprotectedHeader: Partial<JsonWebEncryptionHeaderParameters> | null | undefined,
  recipientUnprotectedHeader: Partial<JsonWebEncryptionHeaderParameters> | null | undefined,
): JsonWebEncryptionHeaderParameters {
  const headerKeys = [
    ...Object.keys(protectedHeader ?? {}),
    ...Object.keys(unprotectedHeader ?? {}),
    ...Object.keys(recipientUnprotectedHeader ?? {}),
  ];

  if (headerKeys.length !== new Set(headerKeys).size) {
    throw new TypeError("Cannot have repeated JSON Web Encryption Header Parameters.");
  }

  return {
    ...protectedHeader,
    ...unprotectedHeader,
    ...recipientUnprotectedHeader,
  } as JsonWebEncryptionHeaderParameters;
}

/**
 * Decodes the provided General JSON Web Encryption Token into its Parameters.
 *
 * @param token General JSON Web Encryption Token.
 * @returns General JSON Web Encryption Parameters.
 * @throws {InvalidJsonWebEncryptionError} The provided JSON Web Encryption is invalid.
 */
export function decode(token: GeneralJsonWebEncryptionToken): GeneralJsonWebEncryptionParameters {
  if (!Objects.isPlain(token) || !isValidGeneralJsonWebEncryptionToken(token)) {
    throw new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
  }

  try {
    let protectedHeader: Partial<JsonWebEncryptionHeaderParameters> | null = null;

    if ("protected" in token) {
      protectedHeader = JSON.parse(Buffer.from(token.protected, "base64url").toString("utf8"));
    }

    const recipients = token.recipients.map<GeneralJsonWebEncryptionParametersRecipient>((tokenRecipient) => ({
      encryptedKey: Buffer.from(tokenRecipient.encrypted_key, "base64url"),
      joseHeader: getJoseHeaderParameters(protectedHeader, token.unprotected, tokenRecipient.header),
      recipientUnprotectedHeader: tokenRecipient.header ?? null,
    }));

    return {
      additionalAuthenticatedData:
        "aad" in token && token.aad.includes(".")
          ? Buffer.from(token.aad.substring(token.aad.indexOf(".") + 1), "base64url")
          : null,
      authenticationTag: Buffer.from(token.tag, "base64url"),
      ciphertext: "ciphertext" in token ? Buffer.from(token.ciphertext, "base64url") : null,
      initializationVector: Buffer.from(token.iv, "base64url"),
      protectedHeader,
      recipients,
      unprotectedHeader: token.unprotected ?? null,
    };
  } catch (error: unknown) {
    throw new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.", { cause: error });
  }
}
