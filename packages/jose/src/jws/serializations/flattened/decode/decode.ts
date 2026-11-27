import { Buffer } from "node:buffer";

import { JSON } from "@avarin/primitives/json";
import { Objects } from "@avarin/primitives/objects";
import { Strings } from "@avarin/primitives/strings";

import { InvalidJoseHeaderError } from "../../../../errors/invalid-jose-header.error.ts";
import { InvalidJsonWebSignatureError } from "../../../../errors/invalid-jsonwebsignature.error.ts";
import { checkPartialJoseHeader } from "../../../../utils/check-partial-jose-header/check-partial-jose-header.ts";
import type { JsonWebSignatureHeaderParameters } from "../../../header/jsonwebsignature.header.parameters.ts";
import type { FlattenedJsonWebSignatureParameters } from "../flattened.jsonwebsignature.parameters.ts";
import type { FlattenedJsonWebSignatureToken } from "../flattened.jsonwebsignature.token.ts";

function isValidFlattenedJsonWebSignatureToken(token: FlattenedJsonWebSignatureToken): boolean {
  try {
    if (!("protected" in token) && !("header" in token)) {
      return false;
    }

    if (
      "protected" in token &&
      (!Strings.isNonEmpty(token.protected) ||
        !checkPartialJoseHeader(JSON.parse(Buffer.from(token.protected, "base64url").toString("utf8"))))
    ) {
      return false;
    }

    if ("header" in token && (!Objects.isPlain(token.header) || !checkPartialJoseHeader(token.header))) {
      return false;
    }

    if ("payload" in token && !Strings.isNonEmpty(token.payload)) {
      return false;
    }

    if (!Strings.isNonEmpty(token.signature)) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

function getJoseHeaderParameters(
  protectedHeader: Partial<JsonWebSignatureHeaderParameters> | null,
  unprotectedHeader: Partial<JsonWebSignatureHeaderParameters> | null,
): JsonWebSignatureHeaderParameters {
  if (!new Set(Object.keys(protectedHeader ?? {})).isDisjointFrom(new Set(Object.keys(unprotectedHeader ?? {})))) {
    throw new TypeError("Cannot have repeated JSON Web Signature Header Parameters.");
  }

  if (unprotectedHeader !== null) {
    if ("crit" in unprotectedHeader) {
      throw new InvalidJoseHeaderError('Invalid JSON Web Signature Unprotected Header Parameter "crit".');
    }

    if ("b64" in unprotectedHeader) {
      throw new InvalidJoseHeaderError('Invalid JSON Web Signature Unprotected Header Parameter "b64".');
    }
  }

  return { ...protectedHeader, ...unprotectedHeader } as JsonWebSignatureHeaderParameters;
}

/**
 * Decodes the provided Flattened JSON Web Signature Token into its Parameters.
 *
 * @param token Flattened JSON Web Signature Token.
 * @returns Flattened JSON Web Signature Parameters.
 * @throws {InvalidJsonWebSignatureError} The provided JSON Web Signature is invalid.
 */
export function decode(token: FlattenedJsonWebSignatureToken): FlattenedJsonWebSignatureParameters {
  if (!Objects.isPlain(token) || !isValidFlattenedJsonWebSignatureToken(token)) {
    throw new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
  }

  try {
    let protectedHeader: Partial<JsonWebSignatureHeaderParameters> | null = null;
    let unprotectedHeader: Partial<JsonWebSignatureHeaderParameters> | null = null;

    if ("protected" in token) {
      protectedHeader = JSON.parse(Buffer.from(token.protected, "base64url").toString("utf8"));
    }

    if ("header" in token) {
      unprotectedHeader = token.header;
    }

    const joseHeader = getJoseHeaderParameters(protectedHeader, unprotectedHeader);

    return {
      joseHeader,
      payload: "payload" in token ? Buffer.from(token.payload, joseHeader.b64 === false ? "utf8" : "base64url") : null,
      protectedHeader: "protected" in token ? protectedHeader : null,
      signature: Buffer.from(token.signature, "base64url"),
      unprotectedHeader: "header" in token ? unprotectedHeader : null,
    };
  } catch (error: unknown) {
    throw new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.", { cause: error });
  }
}
