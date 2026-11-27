import { Buffer } from "node:buffer";

import { Objects } from "@avarin/primitives/objects";

import { InvalidJsonWebSignatureError } from "../../../../errors/invalid-jsonwebsignature.error.ts";
import type { DigitalSignatureAlgorithm } from "../../../../jwa/jws/digital-signature-algorithm.type.ts";
import { DIGITAL_SIGNATURE_BACKEND_REGISTRY } from "../../../../jwa/jws/digital-signature.backend.registry.ts";
import { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import { header as jwsHeader } from "../../../header/index.ts";
import type { JsonWebSignatureHeaderParameters } from "../../../header/jsonwebsignature.header.parameters.ts";
import type { DeserializeOptions } from "../../compact/deserialize/deserialize.options.ts";
import { decode } from "../decode/decode.ts";
import type { FlattenedJsonWebSignatureToken } from "../flattened.jsonwebsignature.token.ts";
import type { FlattenedJsonWebSignature } from "../flattened.jsonwebsignature.ts";

function validateOptions(options: DeserializeOptions): void {
  if (!Objects.isPlain(options)) {
    throw new TypeError("The provided Flattened JSON Web Signature Deserialize Options is invalid.");
  }

  if ("jsonWebKey" in options && options.jsonWebKey !== null && !(options.jsonWebKey instanceof JsonWebKey)) {
    throw new TypeError('The provided Flattened JSON Web Signature Deserialize Option "jsonWebKey" is invalid.');
  }

  if (
    "expectedDigitalSignatureAlgorithms" in options &&
    (!Array.isArray(options.expectedDigitalSignatureAlgorithms) ||
      options.expectedDigitalSignatureAlgorithms.length === 0 ||
      options.expectedDigitalSignatureAlgorithms.some(
        (algorithm) => !DIGITAL_SIGNATURE_BACKEND_REGISTRY.some((backend) => backend.name === algorithm),
      ))
  ) {
    throw new TypeError(
      'The provided Flattened JSON Web Signature Deserialize Option "expectedDigitalSignatureAlgorithms" is invalid.',
    );
  }

  if (
    "detachedPayload" in options &&
    (!Buffer.isBuffer(options.detachedPayload) || options.detachedPayload.byteLength === 0)
  ) {
    throw new TypeError('The provided Flattened JSON Web Signature Deserialize Option "detachedPayload" is invalid.');
  }
}

function validateDetachedPayload(payload: Buffer | null, detachedPayload: Buffer | undefined): void {
  if (!Buffer.isBuffer(payload) && !Buffer.isBuffer(detachedPayload)) {
    throw new InvalidJsonWebSignatureError("The JSON Web Signature requires a valid Payload.");
  }

  if (Buffer.isBuffer(payload) && Buffer.isBuffer(detachedPayload)) {
    throw new InvalidJsonWebSignatureError("The provided JSON Web Signature already has a defined Payload.");
  }
}

function validateExpectedAlgorithms(
  expectedDigitalSignatureAlgorithms: DigitalSignatureAlgorithm[] | undefined,
  parameters: JsonWebSignatureHeaderParameters,
): void {
  if (
    Array.isArray(expectedDigitalSignatureAlgorithms) &&
    !expectedDigitalSignatureAlgorithms.includes(parameters.alg)
  ) {
    throw new InvalidJsonWebSignatureError(`Unexpected Digital Signature Algorithm "${parameters.alg}".`);
  }
}

/**
 * Deserializes the provided Flattened JSON Web Signature Token.
 *
 * @param token Flattened JSON Web Signature Token.
 * @param options Flattened JSON Web Signature deserialize options.
 * @returns Flattened JSON Web Signature.
 * @throws {InvalidJoseHeaderError} The JSON Web Signature Header of the provided Flattened JSON Web Signature Token is
 *   invalid.
 * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to deserialize the Flattened JSON Web
 *   Signature Token.
 * @throws {InvalidJsonWebSignatureError} Failed to deserialize the Flattened JSON Web Signature.
 * @throws {TypeError} One of the provided arguments is invalid.
 */
export async function deserialize(
  token: FlattenedJsonWebSignatureToken,
  options: DeserializeOptions = {},
): Promise<FlattenedJsonWebSignature> {
  validateOptions(options);

  let { joseHeader, payload, protectedHeader, signature, unprotectedHeader } = decode(token);

  validateDetachedPayload(payload, options.detachedPayload);

  const header = await jwsHeader.create(joseHeader);

  if (options.jsonWebKey === null || options.jsonWebKey instanceof JsonWebKey) {
    header.jsonWebKey = options.jsonWebKey;
  }

  const { digitalSignatureBackend, jsonWebKey, parameters } = header;

  validateExpectedAlgorithms(options.expectedDigitalSignatureAlgorithms, parameters);

  payload ??= options.detachedPayload!;

  const encodedProtectedHeader = token.protected ?? "";
  const encodedPayload = payload.toString(parameters.b64 === false ? "utf8" : "base64url");

  const message =
    parameters.b64 === false
      ? Buffer.concat([Buffer.from(`${encodedProtectedHeader}.`, "ascii"), payload])
      : Buffer.from(`${encodedProtectedHeader}.${encodedPayload}`, "ascii");

  await digitalSignatureBackend.verify(signature, message, jsonWebKey);

  return { header, payload, protectedHeader, unprotectedHeader };
}
