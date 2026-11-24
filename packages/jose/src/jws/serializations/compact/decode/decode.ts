import { Buffer } from "node:buffer";

import { Strings } from "@avarin/primitives/strings";

import { InvalidJsonWebSignatureError } from "../../../../errors/invalid-jsonwebsignature.error.ts";
import { header } from "../../../header/index.ts";
import type { CompactJsonWebSignatureParameters } from "../compact.jsonwebsignature.parameters.ts";
import type { CompactJsonWebSignatureToken } from "../compact.jsonwebsignature.token.ts";

/**
 * Decodes the provided Compact JSON Web Signature Token into its Parameters.
 *
 * @param token Compact JSON Web Signature Token.
 * @returns Compact JSON Web Signature Parameters.
 * @throws {InvalidJsonWebSignatureError} The provided JSON Web Signature is invalid.
 */
export async function decode(token: string): Promise<CompactJsonWebSignatureParameters> {
  if (!Strings.isNonEmpty(token)) {
    throw new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
  }

  const tokenParts = token.split(".") as CompactJsonWebSignatureToken;

  if (tokenParts.length !== 3) {
    throw new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
  }

  try {
    const [encodedProtectedHeader, encodedPayload, encodedSignature] = tokenParts;

    const protectedHeader = await header.parse(Buffer.from(encodedProtectedHeader, "base64url").toString("utf8"));
    const payload = Buffer.from(encodedPayload, protectedHeader.parameters.b64 === false ? "utf8" : "base64url");
    const signature = Buffer.from(encodedSignature, "base64url");

    return {
      payload: payload.byteLength > 0 ? payload : null,
      protectedHeader,
      signature,
    };
  } catch (error: unknown) {
    throw new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.", { cause: error });
  }
}
