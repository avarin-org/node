import { Buffer } from "node:buffer";

import { JSON } from "@avarin/primitives/json";
import { Objects } from "@avarin/primitives/objects";

import { InvalidJsonWebSignatureError } from "../../../../errors/invalid-jsonwebsignature.error.ts";
import type { DigitalSignatureAlgorithm } from "../../../../jwa/jws/digital-signature-algorithm.type.ts";
import { DIGITAL_SIGNATURE_BACKEND_REGISTRY } from "../../../../jwa/jws/digital-signature.backend.registry.ts";
import { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import type { JsonWebSignatureHeaderParameters } from "../../../header/jsonwebsignature.header.parameters.ts";
import type { CompactJsonWebSignature } from "../compact.jsonwebsignature.ts";
import { decode } from "../decode/decode.ts";
import type { DeserializeOptions } from "./deserialize.options.ts";

function validateOptions(options: DeserializeOptions): void {
  if (!Objects.isPlain(options)) {
    throw new TypeError("The provided Compact JSON Web Signature Deserialize Options is invalid.");
  }

  if ("jsonWebKey" in options && options.jsonWebKey !== null && !(options.jsonWebKey instanceof JsonWebKey)) {
    throw new TypeError('The provided Compact JSON Web Signature Deserialize Option "jsonWebKey" is invalid.');
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
      'The provided Compact JSON Web Signature Deserialize Option "expectedDigitalSignatureAlgorithms" is invalid.',
    );
  }

  if (
    "detachedPayload" in options &&
    (!Buffer.isBuffer(options.detachedPayload) || options.detachedPayload.byteLength === 0)
  ) {
    throw new TypeError('The provided Compact JSON Web Signature Deserialize Option "detachedPayload" is invalid.');
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
 * Deserializes the provided Compact JSON Web Signature Token.
 *
 * @param token Compact JSON Web Signature Token.
 * @param options Compact JSON Web Signature deserialize options.
 * @returns Compact JSON Web Signature.
 * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to deserialize the Compact JSON Web
 *   Signature Token.
 * @throws {InvalidJsonWebSignatureError} Failed to deserialize the Compact JSON Web Signature.
 * @throws {TypeError} One of the provided arguments is invalid.
 */
export async function deserialize(token: string, options: DeserializeOptions = {}): Promise<CompactJsonWebSignature> {
  validateOptions(options);

  let { payload, protectedHeader, signature } = await decode(token);

  validateDetachedPayload(payload, options.detachedPayload);

  if (options.jsonWebKey === null || options.jsonWebKey instanceof JsonWebKey) {
    protectedHeader.jsonWebKey = options.jsonWebKey;
  }

  const { digitalSignatureBackend, jsonWebKey, parameters } = protectedHeader;

  validateExpectedAlgorithms(options.expectedDigitalSignatureAlgorithms, parameters);

  payload ??= options.detachedPayload!;

  const encodedProtectedHeader = Buffer.from(JSON.stringify(parameters), "utf8").toString("base64url");
  const encodedPayload = payload.toString(parameters.b64 === false ? "utf8" : "base64url");

  const message =
    parameters.b64 === false
      ? Buffer.concat([Buffer.from(`${encodedProtectedHeader}.`, "ascii"), payload])
      : Buffer.from(`${encodedProtectedHeader}.${encodedPayload}`, "ascii");

  await digitalSignatureBackend.verify(signature, message, jsonWebKey);

  return { payload, protectedHeader };
}
