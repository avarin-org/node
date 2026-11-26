import { Buffer } from "node:buffer";

import { Objects } from "@avarin/primitives/objects";

import { InvalidJsonWebEncryptionError } from "../../../../errors/invalid-jsonwebencryption.error.ts";
import type { KeyManagementAlgorithm } from "../../../../jwa/jwe/alg/key-management-algorithm.type.ts";
import { KEY_MANAGEMENT_BACKEND_REGISTRY } from "../../../../jwa/jwe/alg/key-management.backend.registry.ts";
import type { ContentEncryptionAlgorithm } from "../../../../jwa/jwe/enc/content-encryption-algorithm.type.ts";
import { CONTENT_ENCRYPTION_BACKEND_REGISTRY } from "../../../../jwa/jwe/enc/content-encryption.backend.registry.ts";
import type { CompressionAlgorithm } from "../../../../jwa/jwe/zip/compression-algorithm.type.ts";
import { COMPRESSION_BACKEND_REGISTRY } from "../../../../jwa/jwe/zip/compression.backend.registry.ts";
import { CompressionBackend } from "../../../../jwa/jwe/zip/compression.backend.ts";
import { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import type { JsonWebEncryptionHeaderParameters } from "../../../header/jsonwebencryption.header.parameters.ts";
import type { DeserializeOptions } from "../../compact/deserialize/deserialize.options.ts";
import { decode } from "../decode/decode.ts";
import type { FlattenedJsonWebEncryptionToken } from "../flattened.jsonwebencryption.token.ts";
import type { FlattenedJsonWebEncryption } from "../flattened.jsonwebencryption.ts";

function validateOptions(options: DeserializeOptions): void {
  if (!Objects.isPlain(options)) {
    throw new TypeError("The provided Flattened JSON Web Encryption Deserialize Options is invalid.");
  }

  if ("jsonWebKey" in options && !(options.jsonWebKey instanceof JsonWebKey)) {
    throw new TypeError('The provided Flattened JSON Web Encryption Deserialize Option "jsonWebKey" is invalid.');
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
      'The provided Flattened JSON Web Encryption Deserialize Option "expectedKeyManagementAlgorithms" is invalid.',
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
      'The provided Flattened JSON Web Encryption Deserialize Option "expectedContentEncryptionAlgorithms" is invalid.',
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
      'The provided Flattened JSON Web Encryption Deserialize Option "expectedCompressionAlgorithms" is invalid.',
    );
  }

  if (
    "detachedCiphertext" in options &&
    (!Buffer.isBuffer(options.detachedCiphertext) || options.detachedCiphertext.byteLength === 0)
  ) {
    throw new TypeError(
      'The provided Flattened JSON Web Encryption Deserialize Option "detachedCiphertext" is invalid.',
    );
  }
}

function validateDetachedCiphertext(payload: Buffer | null, detachedCiphertext: Buffer | undefined): void {
  if (!Buffer.isBuffer(payload) && !Buffer.isBuffer(detachedCiphertext)) {
    throw new InvalidJsonWebEncryptionError("The JSON Web Encryption requires a valid Ciphertext.");
  }

  if (Buffer.isBuffer(payload) && Buffer.isBuffer(detachedCiphertext)) {
    throw new InvalidJsonWebEncryptionError("The provided JSON Web Encryption already has a defined Ciphertext.");
  }
}

function validateExpectedAlgorithms(
  expectedKeyManagementAlgorithms: KeyManagementAlgorithm[] | undefined,
  expectedContentEncryptionAlgorithms: ContentEncryptionAlgorithm[] | undefined,
  expectedCompressionAlgorithms: CompressionAlgorithm[] | undefined,
  parameters: JsonWebEncryptionHeaderParameters,
): void {
  if (Array.isArray(expectedKeyManagementAlgorithms) && !expectedKeyManagementAlgorithms.includes(parameters.alg)) {
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
 * Deserializes the provided Flattened JSON Web Encryption Token.
 *
 * @param token Flattened JSON Web Encryption Token.
 * @param options Flattened JSON Web Encryption deserialize options.
 * @returns Flattened JSON Web Encryption.
 * @throws {InvalidJsonWebEncryptionError} Failed to deserialize the Flattened JSON Web Encryption.
 * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to deserialize the Flattened JSON Web
 *   Encryption Token.
 * @throws {TypeError} One of the provided arguments is invalid.
 */
export async function deserialize(
  token: FlattenedJsonWebEncryptionToken,
  options: DeserializeOptions = {},
): Promise<FlattenedJsonWebEncryption> {
  validateOptions(options);

  let {
    additionalAuthenticatedData,
    authenticationTag,
    ciphertext,
    encryptedKey,
    header,
    initializationVector,
    protectedHeader,
    recipientUnprotectedHeader,
    unprotectedHeader,
  } = await decode(token);

  validateDetachedCiphertext(ciphertext, options.detachedCiphertext);

  if (options.jsonWebKey instanceof JsonWebKey) {
    header.jsonWebKey = options.jsonWebKey;
  }

  const { compressionBackend, contentEncryptionBackend, jsonWebKey, keyManagementBackend, parameters } = header;

  validateExpectedAlgorithms(
    options.expectedKeyManagementAlgorithms,
    options.expectedContentEncryptionAlgorithms,
    options.expectedCompressionAlgorithms,
    parameters,
  );

  const aadHeader = "protected" in token ? Buffer.from(token.protected, "ascii") : Buffer.alloc(0);

  encryptedKey ??= Buffer.alloc(0);

  additionalAuthenticatedData = Buffer.isBuffer(additionalAuthenticatedData)
    ? Buffer.concat([
        aadHeader,
        Buffer.from(".", "ascii"),
        Buffer.from(additionalAuthenticatedData.toString("base64url"), "ascii"),
      ])
    : aadHeader;

  ciphertext ??= options.detachedCiphertext!;

  const contentEncryptionKey = await keyManagementBackend.unwrap(encryptedKey, jsonWebKey!, header);

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

  return { header, plaintext, protectedHeader, recipientUnprotectedHeader, unprotectedHeader };
}
