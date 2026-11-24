import { Buffer } from "node:buffer";

import { JSON } from "@avarin/primitives/json";
import { Objects } from "@avarin/primitives/objects";

import { InvalidJoseHeaderError } from "../../../../errors/invalid-jose-header.error.ts";
import { InvalidJsonWebSignatureError } from "../../../../errors/invalid-jsonwebsignature.error.ts";
import { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import { checkPartialJoseHeader } from "../../../../utils/check-partial-jose-header/check-partial-jose-header.ts";
import { header } from "../../../header/index.ts";
import type { JsonWebSignatureHeaderParameters } from "../../../header/jsonwebsignature.header.parameters.ts";
import type { JsonWebSignatureHeader } from "../../../header/jsonwebsignature.header.ts";
import type { FlattenedJsonWebSignatureHeaders } from "../flattened.jsonwebsignature.headers.ts";
import type { FlattenedJsonWebSignatureToken } from "../flattened.jsonwebsignature.token.ts";
import type { SerializeOptions } from "./serialize.options.ts";

function validatePayload(payload: Buffer): void {
  if (!Buffer.isBuffer(payload) || payload.byteLength === 0) {
    throw new TypeError("The provided Payload is invalid.");
  }
}

async function validateHeaders(headers: FlattenedJsonWebSignatureHeaders): Promise<JsonWebSignatureHeader> {
  if (!Objects.isPlain(headers)) {
    throw new TypeError("The provided JSON Web Signature Headers is invalid.");
  }

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
    throw new InvalidJoseHeaderError("Missing at least one required JSON Web Signature Header.");
  }

  if (
    !new Set(Object.keys(headers.protectedHeader ?? {})).isDisjointFrom(
      new Set(Object.keys(headers.unprotectedHeader ?? {})),
    )
  ) {
    throw new InvalidJoseHeaderError("Cannot have repeated JSON Web Signature Header Parameters.");
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

  return await header.create(headerParameters);
}

function validateOptions(options: SerializeOptions): void {
  if (!Objects.isPlain(options)) {
    throw new TypeError("The provided Flattened JSON Web Signature Serialize Options is invalid.");
  }

  if ("jsonWebKey" in options && options.jsonWebKey !== null && !(options.jsonWebKey instanceof JsonWebKey)) {
    throw new TypeError('The provided Flattened JSON Web Signature Serialize Option "jsonWebKey" is invalid.');
  }

  if ("detached" in options && typeof options.detached !== "boolean") {
    throw new TypeError('The provided Flattened JSON Web Signature Serialize Option "detached" is invalid.');
  }
}

/**
 * Serializes the provided JSON Web Signature Parameters into a Flattened Token.
 *
 * @param payload JSON Web Signature Payload.
 * @param headers JSON Web Signature Headers Parameters.
 * @param options Flattened JSON Web Signature serialize options.
 * @returns Flattened JSON Web Signature Token.
 * @throws {InvalidJoseHeaderError} One of the provided JSON Web Signature Header Parameters is invalid.
 * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to serialize the Flattened JSON Web
 *   Signature.
 * @throws {InvalidJsonWebSignatureError} Failed to serialize the Flattened JSON Web Signature.
 * @throws {TypeError} One of the provided arguments is invalid.
 */
export async function serialize(
  payload: Buffer,
  headers: FlattenedJsonWebSignatureHeaders,
  options: SerializeOptions = {},
): Promise<FlattenedJsonWebSignatureToken> {
  validatePayload(payload);
  const joseHeader = await validateHeaders(headers);
  validateOptions(options);

  const { digitalSignatureBackend, parameters } = joseHeader;

  const jsonWebKey = options.jsonWebKey ?? joseHeader.jsonWebKey!;

  if (parameters.b64 === false && payload.includes(0x2e) && options.detached !== true) {
    throw new InvalidJsonWebSignatureError("The provided Unencoded Payload cannot be serialized.");
  }

  const encodedProtectedHeader =
    "protectedHeader" in headers
      ? Buffer.from(JSON.stringify(headers.protectedHeader), "utf8").toString("base64url")
      : "";

  const encodedPayload = payload.toString(parameters.b64 === false ? "utf8" : "base64url");

  const message =
    parameters.b64 === false
      ? Buffer.concat([Buffer.from(`${encodedProtectedHeader}.`, "ascii"), payload])
      : Buffer.from(`${encodedProtectedHeader}.${encodedPayload}`, "ascii");

  const signature = await digitalSignatureBackend.sign(message, jsonWebKey);

  const token: FlattenedJsonWebSignatureToken = { signature: signature.toString("base64url") };

  if ("unprotectedHeader" in headers) {
    Reflect.set(token, "header", headers.unprotectedHeader);
  }

  if ("protectedHeader" in headers) {
    Reflect.set(token, "protected", encodedProtectedHeader);
  }

  if (options.detached !== true) {
    Reflect.set(token, "payload", encodedPayload);
  }

  return token;
}
