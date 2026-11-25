import { Buffer } from "node:buffer";

import { JSON } from "@avarin/primitives/json";
import { Objects } from "@avarin/primitives/objects";
import { Strings } from "@avarin/primitives/strings";

import { InvalidJoseHeaderError } from "../../../../errors/invalid-jose-header.error.ts";
import { InvalidJsonWebSignatureError } from "../../../../errors/invalid-jsonwebsignature.error.ts";
import { checkPartialJoseHeader } from "../../../../utils/check-partial-jose-header/check-partial-jose-header.ts";
import { header } from "../../../header/index.ts";
import type { JsonWebSignatureHeaderParameters } from "../../../header/jsonwebsignature.header.parameters.ts";
import type { GeneralJsonWebSignatureHeaders } from "../general.jsonwebsignature.headers.ts";
import type {
  GeneralJsonWebSignatureParameters,
  GeneralJsonWebSignatureParametersSignature,
} from "../general.jsonwebsignature.parameters.ts";
import type { GeneralJsonWebSignatureToken } from "../general.jsonwebsignature.token.ts";
import type { GeneralJsonWebSignatureParsedHeaders } from "../general.jsonwebsignature.ts";

function isValidGeneralJsonWebSignatureToken(token: GeneralJsonWebSignatureToken): boolean {
  if ("payload" in token && !Strings.isNonEmpty(token.payload)) {
    return false;
  }

  if (
    !Array.isArray(token.signatures) ||
    token.signatures.length === 0 ||
    token.signatures.some((signature) => !Objects.isPlain(signature))
  ) {
    return false;
  }

  for (const signature of token.signatures) {
    if (!("protected" in signature) && !("header" in signature)) {
      return false;
    }

    if (
      "protected" in signature &&
      (!Strings.isNonEmpty(signature.protected) ||
        !checkPartialJoseHeader(JSON.parse(Buffer.from(signature.protected, "base64url").toString("utf8"))))
    ) {
      return false;
    }

    if ("header" in signature && !checkPartialJoseHeader(signature.header)) {
      return false;
    }

    if (!Strings.isNonEmpty(signature.signature)) {
      return false;
    }
  }

  return true;
}

async function getJoseHeader(headers: GeneralJsonWebSignatureHeaders): Promise<GeneralJsonWebSignatureParsedHeaders> {
  if (
    !new Set(Object.keys(headers.protectedHeader ?? {})).isDisjointFrom(
      new Set(Object.keys(headers.unprotectedHeader ?? {})),
    )
  ) {
    throw new TypeError("Cannot have repeated JSON Web Signature Header Parameters.");
  }

  if ("unprotectedHeader" in headers) {
    if ("crit" in headers.unprotectedHeader) {
      throw new InvalidJoseHeaderError('Invalid JSON Web Signature Unprotected Parameter "crit".');
    }

    if ("b64" in headers.unprotectedHeader) {
      throw new InvalidJoseHeaderError('Invalid JSON Web Signature Unprotected Parameter "b64".');
    }
  }

  const headerParameters = {
    ...headers.protectedHeader,
    ...headers.unprotectedHeader,
  } as JsonWebSignatureHeaderParameters;

  return {
    header: await header.create(headerParameters),
    protectedHeader: headers.protectedHeader ?? null,
    unprotectedHeader: headers.unprotectedHeader ?? null,
  };
}

/**
 * Decodes the provided General JSON Web Signature Token into its Parameters.
 *
 * @param token General JSON Web Signature Token.
 * @returns General JSON Web Signature Parameters.
 * @throws {InvalidJsonWebSignatureError} The provided JSON Web Signature is invalid.
 */
export async function decode(token: GeneralJsonWebSignatureToken): Promise<GeneralJsonWebSignatureParameters> {
  if (!Objects.isPlain(token) || !isValidGeneralJsonWebSignatureToken(token)) {
    throw new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
  }

  const isUnencodedHeader: boolean[] = [];

  const signatures = await Promise.all(
    token.signatures.map<Promise<GeneralJsonWebSignatureParametersSignature>>(async (signature) => {
      try {
        const headers: GeneralJsonWebSignatureHeaders = {};

        if ("protected" in signature) {
          Reflect.set(
            headers,
            "protectedHeader",
            JSON.parse(Buffer.from(signature.protected, "base64url").toString("utf8")),
          );
        }

        if ("header" in signature) {
          Reflect.set(headers, "unprotectedHeader", signature.header);
        }

        const parsedHeader = await getJoseHeader(headers);

        isUnencodedHeader.push(parsedHeader.header.parameters.b64 === false);

        return {
          header: parsedHeader.header,
          protectedHeader: parsedHeader.protectedHeader,
          signature: Buffer.from(signature.signature, "base64url"),
          unprotectedHeader: parsedHeader.unprotectedHeader,
        };
      } catch (error: unknown) {
        throw new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.", { cause: error });
      }
    }),
  );

  const parameters: GeneralJsonWebSignatureParameters = {
    payload:
      "payload" in token
        ? Buffer.from(token.payload, signatures[0]!.header.parameters.b64 === false ? "utf8" : "base64url")
        : null,
    signatures,
  };

  if (isUnencodedHeader.some((result) => result !== isUnencodedHeader[0])) {
    throw new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
  }

  return parameters;
}
