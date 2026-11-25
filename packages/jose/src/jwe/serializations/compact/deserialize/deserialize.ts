import { Buffer } from "node:buffer";

import { Objects } from "@avarin/primitives/objects";

import { InvalidJsonWebEncryptionError } from "../../../../errors/invalid-jsonwebencryption.error.ts";
import type {
  CompressionAlgorithm,
  ContentEncryptionAlgorithm,
  DigitalSignatureAlgorithm,
} from "../../../../jwa/index.ts";
import { KEY_MANAGEMENT_BACKEND_REGISTRY } from "../../../../jwa/jwe/alg/key-management.backend.registry.ts";
import { CONTENT_ENCRYPTION_BACKEND_REGISTRY } from "../../../../jwa/jwe/enc/content-encryption.backend.registry.ts";
import { COMPRESSION_BACKEND_REGISTRY } from "../../../../jwa/jwe/zip/compression.backend.registry.ts";
import { CompressionBackend } from "../../../../jwa/jwe/zip/compression.backend.ts";
import { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import type { JsonWebEncryptionHeaderParameters } from "../../../header/jsonwebencryption.header.parameters.ts";
import type { CompactJsonWebEncryption } from "../compact.jsonwebencryption.ts";
import { decode } from "../decode/decode.ts";
import type { DeserializeOptions } from "./deserialize.options.ts";

function validateOptions(options: DeserializeOptions): void {
  if (!Objects.isPlain(options)) {
    throw new TypeError("The provided Compact JSON Web Encryption Deserialize Options is invalid.");
  }

  if ("jsonWebKey" in options && !(options.jsonWebKey instanceof JsonWebKey)) {
    throw new TypeError('The provided Compact JSON Web Encryption Deserialize Option "jsonWebKey" is invalid.');
  }

  if (
    "expectedKeyManagementAlgorithms" in options &&
    (!Array.isArray(options.expectedKeyManagementAlgorithms) ||
      options.expectedKeyManagementAlgorithms.length === 0 ||
      options.expectedKeyManagementAlgorithms.some(
        (algorithm) => !KEY_MANAGEMENT_BACKEND_REGISTRY.some((backend) => backend.name === algorithm),
      ))
  ) {
    throw new TypeError(
      'The provided Compact JSON Web Encryption Deserialize Option "expectedKeyManagementAlgorithms" is invalid.',
    );
  }

  if (
    "expectedContentEncryptionAlgorithms" in options &&
    (!Array.isArray(options.expectedContentEncryptionAlgorithms) ||
      options.expectedContentEncryptionAlgorithms.length === 0 ||
      options.expectedContentEncryptionAlgorithms.some(
        (algorithm) => !CONTENT_ENCRYPTION_BACKEND_REGISTRY.some((backend) => backend.name === algorithm),
      ))
  ) {
    throw new TypeError(
      'The provided Compact JSON Web Encryption Deserialize Option "expectedContentEncryptionAlgorithms" is invalid.',
    );
  }

  if (
    "expectedCompressionAlgorithms" in options &&
    (!Array.isArray(options.expectedCompressionAlgorithms) ||
      options.expectedCompressionAlgorithms.length === 0 ||
      options.expectedCompressionAlgorithms.some(
        (algorithm) => !COMPRESSION_BACKEND_REGISTRY.some((backend) => backend.name === algorithm),
      ))
  ) {
    throw new TypeError(
      'The provided Compact JSON Web Encryption Deserialize Option "expectedCompressionAlgorithms" is invalid.',
    );
  }

  if (
    "detachedCiphertext" in options &&
    (!Buffer.isBuffer(options.detachedCiphertext) || options.detachedCiphertext.byteLength === 0)
  ) {
    throw new TypeError('The provided Compact JSON Web Encryption Deserialize Option "detachedCiphertext" is invalid.');
  }
}

function validateDetachedCiphertext(ciphertext: Buffer | null, detachedCiphertext: Buffer | undefined): void {
  if (!Buffer.isBuffer(ciphertext) && !Buffer.isBuffer(detachedCiphertext)) {
    throw new InvalidJsonWebEncryptionError("The JSON Web Encryption requires a valid Ciphertext.");
  }

  if (Buffer.isBuffer(ciphertext) && Buffer.isBuffer(detachedCiphertext)) {
    throw new InvalidJsonWebEncryptionError("The provided JSON Web Encryption already has a defined Ciphertext.");
  }
}

function validateExpectedAlgorithms(
  expectedDigitalSignatureAlgorithms: DigitalSignatureAlgorithm[] | undefined,
  expectedContentEncryptionAlgorithms: ContentEncryptionAlgorithm[] | undefined,
  expectedCompressionAlgorithms: CompressionAlgorithm[] | undefined,
  parameters: JsonWebEncryptionHeaderParameters,
): void {
  if (
    Array.isArray(expectedDigitalSignatureAlgorithms) &&
    !expectedDigitalSignatureAlgorithms.includes(parameters.alg)
  ) {
    throw new InvalidJsonWebEncryptionError(`Unexpected Key Management Algorithm "${parameters.alg}".`);
  }

  if (
    Array.isArray(expectedContentEncryptionAlgorithms) &&
    !expectedContentEncryptionAlgorithms.includes(parameters.enc)
  ) {
    throw new InvalidJsonWebEncryptionError(`Unexpected Content Encryption Algorithm "${parameters.enc}".`);
  }

  if (Array.isArray(expectedCompressionAlgorithms) && !expectedCompressionAlgorithms.includes(parameters.zip!)) {
    throw new InvalidJsonWebEncryptionError(`Unexpected Compression Algorithm "${parameters.zip ?? ""}".`);
  }
}

/**
 * Deserializes the provided Compact JSON Web Encryption Token.
 *
 * @param token Compact JSON Web Encryption Token.
 * @param options Compact JSON Web Encryption deserialize options.
 * @returns Compact JSON Web Encryption.
 * @throws {InvalidJsonWebEncryptionError} Failed to deserialize the Compact JSON Web Encryption.
 * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to deserialize the Compact JSON Web
 *   Encryption Token.
 * @throws {TypeError} One of the provided arguments is invalid.
 */
export async function deserialize(token: string, options: DeserializeOptions = {}): Promise<CompactJsonWebEncryption> {
  validateOptions(options);

  let {
    additionalAuthenticatedData,
    authenticationTag,
    encryptedKey,
    initializationVector,
    protectedHeader,
    ciphertext,
  } = await decode(token);

  validateDetachedCiphertext(ciphertext, options.detachedCiphertext);

  if (options.jsonWebKey instanceof JsonWebKey) {
    protectedHeader.jsonWebKey = options.jsonWebKey;
  }

  const { compressionBackend, contentEncryptionBackend, keyManagementBackend, parameters } = protectedHeader;

  validateExpectedAlgorithms(
    options.expectedKeyManagementAlgorithms,
    options.expectedContentEncryptionAlgorithms,
    options.expectedCompressionAlgorithms,
    parameters,
  );

  ciphertext ??= options.detachedCiphertext!;

  const contentEncryptionKey = await keyManagementBackend.unwrap(
    encryptedKey,
    protectedHeader.jsonWebKey!,
    protectedHeader,
  );

  let plaintext = await contentEncryptionBackend.decrypt(
    ciphertext,
    contentEncryptionKey,
    additionalAuthenticatedData,
    initializationVector,
    authenticationTag,
  );

  if (compressionBackend instanceof CompressionBackend) {
    plaintext = await compressionBackend.decompress(plaintext);
  }

  return { plaintext, protectedHeader };
}
