import { Buffer } from "node:buffer";

import { JSON } from "@avarin/primitives/json";
import { Objects } from "@avarin/primitives/objects";

import { InvalidJoseHeaderError } from "../../../../errors/invalid-jose-header.error.ts";
import { InvalidJsonWebSignatureError } from "../../../../errors/invalid-jsonwebsignature.error.ts";
import { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import { checkPartialJoseHeader } from "../../../../utils/check-partial-jose-header/check-partial-jose-header.ts";
import { header } from "../../../header/index.ts";
import type { JsonWebSignatureHeaderParameters } from "../../../header/jsonwebsignature.header.parameters.ts";
import type { GeneralJsonWebSignatureHeaders } from "../general.jsonwebsignature.headers.ts";
import type {
  GeneralJsonWebSignatureToken,
  GeneralJsonWebSignatureTokenSignature,
} from "../general.jsonwebsignature.token.ts";
import type { GeneralJsonWebSignatureParsedHeaders } from "../general.jsonwebsignature.ts";
import type { SerializeOptions } from "./serialize.options.ts";

function validatePayload(payload: Buffer): void {
  if (!Buffer.isBuffer(payload) || payload.byteLength === 0) {
    throw new TypeError("The provided Payload is invalid.");
  }
}

async function validateHeaders(
  headersCollection: GeneralJsonWebSignatureHeaders[],
): Promise<GeneralJsonWebSignatureParsedHeaders[]> {
  if (
    !Array.isArray(headersCollection) ||
    headersCollection.length === 0 ||
    headersCollection.some((headers) => !Objects.isPlain(headers))
  ) {
    throw new TypeError("The provided JSON Web Signature Headers is invalid.");
  }

  const isUnencodedHeader: boolean[] = [];

  const parsedHeadersCollection = await Promise.all(
    headersCollection.map(async (headers) => {
      if (
        "protectedHeader" in headers &&
        (!Objects.isPlain(headers.protectedHeader) || !checkPartialJoseHeader(headers.protectedHeader))
      ) {
        throw new TypeError("The provided JSON Web Signature Protected Header is invalid.");
      }

      if (
        "unprotectedHeader" in headers &&
        (!Objects.isPlain(headers.unprotectedHeader) || !checkPartialJoseHeader(headers.unprotectedHeader))
      ) {
        throw new TypeError("The provided JSON Web Signature Unprotected Header is invalid.");
      }

      if (!("protectedHeader" in headers) && !("unprotectedHeader" in headers)) {
        throw new TypeError("Missing at least one required JSON Web Signature Header.");
      }

      if (
        !new Set(Object.keys(headers.protectedHeader ?? {})).isDisjointFrom(
          new Set(Object.keys(headers.unprotectedHeader ?? {})),
        )
      ) {
        throw new TypeError("Cannot have repeated JSON Web Signature Header Parameters.");
      }

      if ("unprotectedHeader" in headers) {
        if ("crit" in headers.unprotectedHeader) {
          throw new InvalidJoseHeaderError('Invalid JSON Web Signature Unprotected Header Parameter "crit".');
        }

        if ("b64" in headers.unprotectedHeader) {
          throw new InvalidJoseHeaderError('Invalid JSON Web Signature Unprotected Header Parameter "b64".');
        }
      }

      const headerParameters = {
        ...headers.protectedHeader,
        ...headers.unprotectedHeader,
      } as JsonWebSignatureHeaderParameters;

      const parsedHeaders: GeneralJsonWebSignatureParsedHeaders = {
        header: await header.create(headerParameters),
        protectedHeader: headers.protectedHeader ?? null,
        unprotectedHeader: headers.unprotectedHeader ?? null,
      };

      isUnencodedHeader.push(headerParameters.b64 === false);

      return parsedHeaders;
    }),
  );

  if (isUnencodedHeader.some((result) => result !== isUnencodedHeader[0])) {
    throw new InvalidJoseHeaderError('Mismatching JSON Web Signature Headers Parameter "b64".');
  }

  return parsedHeadersCollection;
}

function validateOptions(options: SerializeOptions, parsedHeaders: GeneralJsonWebSignatureParsedHeaders[]): void {
  if (!Objects.isPlain(options)) {
    throw new TypeError("The provided General JSON Web Signature Serialize Options is invalid.");
  }

  if (
    "jsonWebKeys" in options &&
    (!Array.isArray(options.jsonWebKeys) ||
      options.jsonWebKeys.length === 0 ||
      options.jsonWebKeys.some((jwk) => jwk !== null && !(jwk instanceof JsonWebKey)) ||
      options.jsonWebKeys.length !== parsedHeaders.length)
  ) {
    throw new TypeError('The provided General JSON Web Signature Serialize Option "jsonWebKeys" is invalid.');
  }

  if ("detached" in options && typeof options.detached !== "boolean") {
    throw new TypeError('The provided General JSON Web Signature Serialize Option "detached" is invalid.');
  }
}

/**
 * Serializes the provided JSON Web Signature Parameters into a General Token.
 *
 * @param payload JSON Web Signature Payload.
 * @param headers JSON Web Signature Headers Parameters.
 * @param options General JSON Web Signature serialize options.
 * @returns General JSON Web Signature Token.
 * @throws {InvalidJoseHeaderError} One of the provided JSON Web Signature Header Parameters is invalid.
 * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to serialize the General JSON Web
 *   Signature.
 * @throws {InvalidJsonWebSignatureError} Failed to serialize the General JSON Web Signature.
 * @throws {TypeError} One of the provided arguments is invalid.
 */
export async function serialize(
  payload: Buffer,
  headers: GeneralJsonWebSignatureHeaders[],
  options: SerializeOptions = {},
): Promise<GeneralJsonWebSignatureToken> {
  validatePayload(payload);
  const parsedHeadersCollection = await validateHeaders(headers);
  validateOptions(options, parsedHeadersCollection);

  const isPayloadUnencoded = parsedHeadersCollection[0]!.header.parameters.b64 === false;

  if (isPayloadUnencoded && payload.includes(0x2e) && options.detached !== true) {
    throw new InvalidJsonWebSignatureError("The provided Unencoded Payload cannot be serialized.");
  }

  const token: GeneralJsonWebSignatureToken = {
    signatures: await Promise.all(
      parsedHeadersCollection.map(async (parsedHeaders, index) => {
        const jwk = options.jsonWebKeys?.[index];
        const jsonWebKey = jwk === null || jwk instanceof JsonWebKey ? jwk : parsedHeaders.header.jsonWebKey;

        const encodedProtectedHeader = Objects.isPlain(parsedHeaders.protectedHeader)
          ? Buffer.from(JSON.stringify(parsedHeaders.protectedHeader), "utf8").toString("base64url")
          : "";

        const message = isPayloadUnencoded
          ? Buffer.concat([Buffer.from(`${encodedProtectedHeader}.`, "ascii"), payload])
          : Buffer.from(`${encodedProtectedHeader}.${payload.toString("base64url")}`, "ascii");

        const signature = await parsedHeaders.header.digitalSignatureBackend.sign(message, jsonWebKey);

        const signaturesParameters: GeneralJsonWebSignatureTokenSignature = {
          signature: signature.toString("base64url"),
        };

        if (Objects.isPlain(parsedHeaders.protectedHeader)) {
          Reflect.set(signaturesParameters, "protected", encodedProtectedHeader);
        }

        if (Objects.isPlain(parsedHeaders.unprotectedHeader)) {
          Reflect.set(signaturesParameters, "header", parsedHeaders.unprotectedHeader);
        }

        return signaturesParameters;
      }),
    ),
  };

  if (options.detached !== true) {
    Reflect.set(token, "payload", payload.toString(isPayloadUnencoded ? "utf8" : "base64url"));
  }

  return token;
}
