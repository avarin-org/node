import { Buffer } from "node:buffer";

import { JSON } from "@avarin/primitives/json";
import { Strings } from "@avarin/primitives/strings";

import { InvalidJsonWebSignatureError } from "../../../../errors/invalid-jsonwebsignature.error.ts";
import type { JsonWebSignatureHeaderParameters } from "../../../header/jsonwebsignature.header.parameters.ts";
import type { CompactJsonWebSignatureParameters } from "../compact.jsonwebsignature.parameters.ts";
import type { CompactJsonWebSignatureToken } from "../compact.jsonwebsignature.token.ts";

/**
 * Decodes the provided Compact JSON Web Signature Token into its Parameters.
 *
 * @param token Compact JSON Web Signature Token.
 * @returns Compact JSON Web Signature Parameters.
 * @throws {InvalidJsonWebSignatureError} The provided JSON Web Signature is invalid.
 */
export function decode(token: string): CompactJsonWebSignatureParameters {
  if (!Strings.isNonEmpty(token)) {
    throw new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
  }

  const tokenParts = token.split(".") as CompactJsonWebSignatureToken;

  if (tokenParts.length !== 3) {
    throw new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
  }

  try {
    const [encodedProtectedHeader, encodedPayload, encodedSignature] = tokenParts;

    const joseHeader = JSON.parse<JsonWebSignatureHeaderParameters>(
      Buffer.from(encodedProtectedHeader, "base64url").toString("utf8"),
    );

    const payload = Buffer.from(encodedPayload, joseHeader.b64 === false ? "utf8" : "base64url");
    const signature = Buffer.from(encodedSignature, "base64url");

    return {
      joseHeader,
      payload: payload.byteLength > 0 ? payload : null,
      signature,
    };
  } catch (error: unknown) {
    throw new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.", { cause: error });
  }
}
