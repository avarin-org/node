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
import { decode } from "../decode/decode.ts";
import type { GeneralJsonWebEncryptionParametersRecipient } from "../general.jsonwebencryption.parameters.ts";
import type { GeneralJsonWebEncryptionToken } from "../general.jsonwebencryption.token.ts";
import type { GeneralJsonWebEncryption, GeneralJsonWebEncryptionRecipient } from "../general.jsonwebencryption.ts";
import type { DeserializeOptions } from "./deserialize.options.ts";

function validateOptions(options: DeserializeOptions, recipients: GeneralJsonWebEncryptionParametersRecipient[]): void {
  if (!Objects.isPlain(options)) {
    throw new TypeError("The provided General JSON Web Encryption Deserialize Options is invalid.");
  }

  if (
    "detachedCiphertext" in options &&
    (!Buffer.isBuffer(options.detachedCiphertext) || options.detachedCiphertext.byteLength === 0)
  ) {
    throw new TypeError('The provided General JSON Web Encryption Deserialize Option "detachedCiphertext" is invalid.');
  }

  if ("recipients" in options) {
    if (
      !Array.isArray(options.recipients) ||
      options.recipients.length === 0 ||
      options.recipients.some((recipientOptions) => !Objects.isPlain(recipientOptions))
    ) {
      throw new TypeError('The provided General JSON Web Encryption Deserialize Option "recipients" is invalid.');
    }

    options.recipients.forEach((recipientOptions) => {
      if ("jsonWebKey" in recipientOptions && !(recipientOptions.jsonWebKey instanceof JsonWebKey)) {
        throw new TypeError(
          'The provided General JSON Web Encryption Deserialize Recipient Option "jsonWebKey" is invalid.',
        );
      }

      if (
        "expectedKeyManagementAlgorithms" in recipientOptions &&
        (!Array.isArray(recipientOptions.expectedKeyManagementAlgorithms) ||
          recipientOptions.expectedKeyManagementAlgorithms.length === 0 ||
          recipientOptions.expectedKeyManagementAlgorithms.some(
            (algorithm) => !KEY_MANAGEMENT_BACKEND_REGISTRY.some((backend) => backend.name === algorithm),
          ))
      ) {
        throw new TypeError(
          'The provided General JSON Web Encryption Deserialize Recipient Option "expectedKeyManagementAlgorithms" is invalid.',
        );
      }

      if (
        "expectedContentEncryptionAlgorithms" in recipientOptions &&
        (!Array.isArray(recipientOptions.expectedContentEncryptionAlgorithms) ||
          recipientOptions.expectedContentEncryptionAlgorithms.length === 0 ||
          recipientOptions.expectedContentEncryptionAlgorithms.some(
            (algorithm) => !CONTENT_ENCRYPTION_BACKEND_REGISTRY.some((backend) => backend.name === algorithm),
          ))
      ) {
        throw new TypeError(
          'The provided General JSON Web Encryption Deserialize Recipient Option "expectedContentEncryptionAlgorithms" is invalid.',
        );
      }

      if (
        "expectedCompressionAlgorithms" in recipientOptions &&
        (!Array.isArray(recipientOptions.expectedCompressionAlgorithms) ||
          recipientOptions.expectedCompressionAlgorithms.length === 0 ||
          recipientOptions.expectedCompressionAlgorithms.some(
            (algorithm) => !COMPRESSION_BACKEND_REGISTRY.some((backend) => backend.name === algorithm),
          ))
      ) {
        throw new TypeError(
          'The provided General JSON Web Encryption Deserialize Recipient Option "expectedCompressionAlgorithms" is invalid.',
        );
      }
    });

    if (options.recipients.length !== recipients.length) {
      throw new TypeError(
        'The length of the General JSON Web Encryption Deserialize Option "recipients" and the General JSON Web Encryption Token Signatures do not match.',
      );
    }
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
 * Deserializes the provided General JSON Web Encryption Token.
 *
 * @param token General JSON Web Encryption Token.
 * @param options General JSON Web Encryption deserialize options.
 * @returns General JSON Web Encryption.
 * @throws {InvalidJsonWebEncryptionError} Failed to deserialize the General JSON Web Encryption.
 * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to deserialize the General JSON Web
 *   Signature Token.
 * @throws {TypeError} One of the provided arguments is invalid.
 */
export async function deserialize(
  token: GeneralJsonWebEncryptionToken,
  options: DeserializeOptions = {},
): Promise<GeneralJsonWebEncryption> {
  let {
    additionalAuthenticatedData,
    authenticationTag,
    ciphertext,
    initializationVector,
    protectedHeader,
    recipients,
    unprotectedHeader,
  } = await decode(token);

  validateOptions(options, recipients);
  validateDetachedCiphertext(ciphertext, options.detachedCiphertext);

  const aadHeader = "protected" in token ? Buffer.from(token.protected, "ascii") : Buffer.alloc(0);

  additionalAuthenticatedData = Buffer.isBuffer(additionalAuthenticatedData)
    ? Buffer.concat([
        aadHeader,
        Buffer.from(".", "ascii"),
        Buffer.from(additionalAuthenticatedData.toString("base64url"), "ascii"),
      ])
    : aadHeader;

  ciphertext ??= options.detachedCiphertext!;

  const recipientsPromises: Promise<GeneralJsonWebEncryptionRecipient>[] = [];
  const plaintexts: Buffer[] = [];

  for (let i = 0; i < recipients.length; i += 1) {
    recipientsPromises.push(
      (async (): Promise<GeneralJsonWebEncryptionRecipient> => {
        const { encryptedKey, header, recipientUnprotectedHeader } = recipients[i]!;

        const recipientOptions = options.recipients?.[i] ?? {};

        if (recipientOptions.jsonWebKey instanceof JsonWebKey) {
          header.jsonWebKey = recipientOptions.jsonWebKey;
        }

        const { compressionBackend, contentEncryptionBackend, jsonWebKey, keyManagementBackend, parameters } = header;

        validateExpectedAlgorithms(
          recipientOptions.expectedKeyManagementAlgorithms,
          recipientOptions.expectedContentEncryptionAlgorithms,
          recipientOptions.expectedCompressionAlgorithms,
          parameters,
        );

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

        plaintexts.push(plaintext);

        return { header, recipientUnprotectedHeader };
      })(),
    );
  }

  const resolvedRecipients = await Promise.all(recipientsPromises);

  return { plaintext: plaintexts[0]!, protectedHeader, recipients: resolvedRecipients, unprotectedHeader };
}
