import { Buffer } from "node:buffer";

import { JSON } from "@avarin/primitives/json";
import { Objects } from "@avarin/primitives/objects";

import { InvalidJsonWebSignatureError } from "../../../../errors/invalid-jsonwebsignature.error.ts";
import { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import { header } from "../../../header/index.ts";
import type { JsonWebSignatureHeaderParameters } from "../../../header/jsonwebsignature.header.parameters.ts";
import type { SerializeOptions } from "./serialize.options.ts";

function validatePayload(payload: Buffer): void {
  if (!Buffer.isBuffer(payload) || payload.byteLength === 0) {
    throw new TypeError("The provided Payload is invalid.");
  }
}

function validateProtectedHeader(protectedHeader: JsonWebSignatureHeaderParameters): void {
  if (!header.check(protectedHeader)) {
    throw new TypeError("The provided JSON Web Signature Protected Header is invalid.");
  }
}

function validateOptions(options: SerializeOptions): void {
  if (!Objects.isPlain(options)) {
    throw new TypeError("The provided Compact JSON Web Signature Serialize Options is invalid.");
  }

  if ("jsonWebKey" in options && !(options.jsonWebKey instanceof JsonWebKey)) {
    throw new TypeError('The provided Compact JSON Web Signature Serialize Option "jsonWebKey" is invalid.');
  }

  if ("detached" in options && typeof options.detached !== "boolean") {
    throw new TypeError('The provided Compact JSON Web Signature Serialize Option "detached" is invalid.');
  }
}

/**
 * Serializes the provided JSON Web Signature Parameters into a Compact Token.
 *
 * @param payload JSON Web Signature Payload.
 * @param protectedHeaderParameters JSON Web Signature Protected Header Parameters.
 * @param options Compact JSON Web Signature serialize options.
 * @returns Compact JSON Web Signature Token.
 * @throws {InvalidJoseHeaderError} The provided JSON Web Signature Protected Header Parameters is invalid.
 * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to serialize the Compact JSON Web
 *   Signature.
 * @throws {InvalidJsonWebSignatureError} Failed to serialize the Compact JSON Web Signature.
 * @throws {TypeError} One of the provided arguments is invalid.
 */
export async function serialize(
  payload: Buffer,
  protectedHeaderParameters: JsonWebSignatureHeaderParameters,
  options: SerializeOptions = {},
): Promise<string> {
  validatePayload(payload);
  validateProtectedHeader(protectedHeaderParameters);
  validateOptions(options);

  const protectedHeader = await header.create(protectedHeaderParameters);

  const { digitalSignatureBackend, parameters } = protectedHeader;

  const jsonWebKey = options.jsonWebKey ?? protectedHeader.jsonWebKey!;

  if (parameters.b64 === false && payload.includes(0x2e) && options.detached !== true) {
    throw new InvalidJsonWebSignatureError("The provided Unencoded Payload cannot be serialized.");
  }

  const encodedProtectedHeader = Buffer.from(JSON.stringify(parameters), "utf8").toString("base64url");
  const encodedPayload = payload.toString(parameters.b64 === false ? "utf8" : "base64url");

  const message =
    parameters.b64 === false
      ? Buffer.concat([Buffer.from(`${encodedProtectedHeader}.`, "ascii"), payload])
      : Buffer.from(`${encodedProtectedHeader}.${encodedPayload}`, "ascii");

  const signature = await digitalSignatureBackend.sign(message, jsonWebKey);
  const encodedSignature = signature.toString("base64url");

  return `${encodedProtectedHeader}.${options.detached ? "" : encodedPayload}.${encodedSignature}`;
}
