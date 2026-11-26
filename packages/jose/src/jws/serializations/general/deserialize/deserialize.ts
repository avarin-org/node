import { Buffer } from "node:buffer";

import { Objects } from "@avarin/primitives/objects";

import { InvalidJsonWebSignatureError } from "../../../../errors/invalid-jsonwebsignature.error.ts";
import type { DigitalSignatureAlgorithm } from "../../../../jwa/jws/digital-signature-algorithm.type.ts";
import { DIGITAL_SIGNATURE_BACKEND_REGISTRY } from "../../../../jwa/jws/digital-signature.backend.registry.ts";
import { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import type { JsonWebSignatureHeaderParameters } from "../../../header/jsonwebsignature.header.parameters.ts";
import { decode } from "../decode/decode.ts";
import type { GeneralJsonWebSignatureParametersSignature } from "../general.jsonwebsignature.parameters.ts";
import type { GeneralJsonWebSignatureToken } from "../general.jsonwebsignature.token.ts";
import type { GeneralJsonWebSignature, GeneralJsonWebSignatureParsedHeaders } from "../general.jsonwebsignature.ts";
import type { DeserializeOptions } from "./deserialize.options.ts";

function validateOptions(options: DeserializeOptions, signatures: GeneralJsonWebSignatureParametersSignature[]): void {
  if (!Objects.isPlain(options)) {
    throw new TypeError("The provided General JSON Web Signature Deserialize Options is invalid.");
  }

  if (
    "detachedPayload" in options &&
    (!Buffer.isBuffer(options.detachedPayload) || options.detachedPayload.byteLength === 0)
  ) {
    throw new TypeError('The provided General JSON Web Signature Deserialize Option "detachedPayload" is invalid.');
  }

  if ("signatures" in options) {
    if (
      !Array.isArray(options.signatures) ||
      options.signatures.length === 0 ||
      options.signatures.some((signatureOptions) => !Objects.isPlain(signatureOptions))
    ) {
      throw new TypeError('The provided General JSON Web Signature Deserialize Option "signatures" is invalid.');
    }

    options.signatures.forEach((signatureOptions) => {
      if (
        "jsonWebKey" in signatureOptions &&
        signatureOptions.jsonWebKey !== null &&
        !(signatureOptions.jsonWebKey instanceof JsonWebKey)
      ) {
        throw new TypeError(
          'The provided General JSON Web Signature Deserialize Signature Option "jsonWebKey" is invalid.',
        );
      }

      if (
        "expectedDigitalSignatureAlgorithms" in signatureOptions &&
        (!Array.isArray(signatureOptions.expectedDigitalSignatureAlgorithms) ||
          signatureOptions.expectedDigitalSignatureAlgorithms.length === 0 ||
          signatureOptions.expectedDigitalSignatureAlgorithms.some(
            (algorithm) => !DIGITAL_SIGNATURE_BACKEND_REGISTRY.some((backend) => backend.name === algorithm),
          ))
      ) {
        throw new TypeError(
          'The provided General JSON Web Signature Deserialize Signature Option "expectedDigitalSignatureAlgorithms" is invalid.',
        );
      }
    });

    if (options.signatures.length !== signatures.length) {
      throw new TypeError(
        'The length of the General JSON Web Signature Deserialize Option "signatures" and the General JSON Web Signature Token Signatures do not match.',
      );
    }
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
 * Deserializes the provided General JSON Web Signature Token.
 *
 * @param token General JSON Web Signature Token.
 * @param options General JSON Web Signature deserialize options.
 * @returns General JSON Web Signature.
 * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to deserialize the General JSON Web
 *   Signature Token.
 * @throws {InvalidJsonWebSignatureError} Failed to deserialize the General JSON Web Signature.
 * @throws {TypeError} One of the provided arguments is invalid.
 */
export async function deserialize(
  token: GeneralJsonWebSignatureToken,
  options: DeserializeOptions = {},
): Promise<GeneralJsonWebSignature> {
  let { payload, signatures } = await decode(token);

  validateOptions(options, signatures);
  validateDetachedPayload(payload, options.detachedPayload);

  payload ??= options.detachedPayload!;

  const headersPromises: Promise<GeneralJsonWebSignatureParsedHeaders>[] = [];

  for (let i = 0; i < signatures.length; i += 1) {
    headersPromises.push(
      (async (): Promise<GeneralJsonWebSignatureParsedHeaders> => {
        const { header, protectedHeader, signature, unprotectedHeader } = signatures[i]!;
        const signatureOptions = options.signatures?.[i] ?? {};

        if (signatureOptions.jsonWebKey === null || signatureOptions.jsonWebKey instanceof JsonWebKey) {
          header.jsonWebKey = signatureOptions.jsonWebKey;
        }

        const { digitalSignatureBackend, jsonWebKey, parameters } = header;

        validateExpectedAlgorithms(signatureOptions.expectedDigitalSignatureAlgorithms, parameters);

        const encodedProtectedHeader = token.signatures[i]!.protected ?? "";
        const encodedPayload = payload.toString(parameters.b64 === false ? "utf8" : "base64url");

        const message =
          parameters.b64 === false
            ? Buffer.concat([Buffer.from(`${encodedProtectedHeader}.`, "ascii"), payload])
            : Buffer.from(`${encodedProtectedHeader}.${encodedPayload}`, "ascii");

        await digitalSignatureBackend.verify(signature, message, jsonWebKey);

        return { header, protectedHeader, unprotectedHeader };
      })(),
    );
  }

  return { headers: await Promise.all(headersPromises), payload };
}
