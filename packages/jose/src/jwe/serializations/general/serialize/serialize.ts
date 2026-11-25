import { Buffer } from "node:buffer";
import { randomBytes } from "node:crypto";
import { promisify } from "node:util";

import { JSON } from "@avarin/primitives/json";
import { Objects } from "@avarin/primitives/objects";

import { InvalidJoseHeaderError } from "../../../../errors/invalid-jose-header.error.ts";
import { CompressionBackend } from "../../../../jwa/jwe/zip/compression.backend.ts";
import { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import { checkPartialJoseHeader } from "../../../../utils/check-partial-jose-header/check-partial-jose-header.ts";
import { header } from "../../../header/index.ts";
import type { JsonWebEncryptionHeaderParameters } from "../../../header/jsonwebencryption.header.parameters.ts";
import type { GeneralJsonWebEncryptionHeaders } from "../general.jsonwebencryption.headers.ts";
import type {
  GeneralJsonWebEncryptionToken,
  GeneralJsonWebEncryptionTokenRecipient,
} from "../general.jsonwebencryption.token.ts";
import type { GeneralJsonWebEncryptionRecipient } from "../general.jsonwebencryption.ts";
import type { SerializeOptions } from "./serialize.options.ts";

const randomBytesAsync = promisify(randomBytes);

function validatePlaintext(plaintext: Buffer): void {
  if (!Buffer.isBuffer(plaintext) || plaintext.byteLength === 0) {
    throw new TypeError("The provided Plaintext is invalid.");
  }
}

async function validateHeaders(headers: GeneralJsonWebEncryptionHeaders): Promise<GeneralJsonWebEncryptionRecipient[]> {
  if (
    "protectedHeader" in headers &&
    (!Objects.isPlain(headers.protectedHeader) || !checkPartialJoseHeader(headers.protectedHeader))
  ) {
    throw new TypeError("The provided JSON Web Encryption Protected Header is invalid.");
  }

  if (
    "unprotectedHeader" in headers &&
    (!Objects.isPlain(headers.unprotectedHeader) || !checkPartialJoseHeader(headers.unprotectedHeader))
  ) {
    throw new TypeError("The provided JSON Web Encryption Unprotected Header is invalid.");
  }

  if (
    !Array.isArray(headers.recipients) ||
    headers.recipients.length === 0 ||
    headers.recipients.some((recipient) => !Objects.isPlain(recipient))
  ) {
    throw new TypeError("The provided JSON Web Encryption Recipients is invalid.");
  }

  const recipients = await Promise.all(
    headers.recipients.map<Promise<GeneralJsonWebEncryptionRecipient>>(async (recipient) => {
      if (
        "recipientUnprotectedHeader" in recipient &&
        (!Objects.isPlain(recipient.recipientUnprotectedHeader) ||
          !checkPartialJoseHeader(recipient.recipientUnprotectedHeader))
      ) {
        throw new TypeError("The provided JSON Web Encryption Recipient Unprotected Header is invalid.");
      }

      if (
        !("protectedHeader" in headers) &&
        !("unprotectedHeader" in headers) &&
        !("recipientUnprotectedHeader" in recipient)
      ) {
        throw new TypeError("Missing at least one required JSON Web Encryption Header.");
      }

      const headerKeys = [
        ...Object.keys(headers.protectedHeader ?? {}),
        ...Object.keys(headers.unprotectedHeader ?? {}),
        ...Object.keys(recipient.recipientUnprotectedHeader ?? {}),
      ];

      if (headerKeys.length !== new Set(headerKeys).size) {
        throw new TypeError("Cannot have repeated JSON Web Encryption Header Parameters.");
      }

      const headerParameters = {
        ...headers.protectedHeader,
        ...headers.unprotectedHeader,
        ...recipient.recipientUnprotectedHeader,
      } as JsonWebEncryptionHeaderParameters;

      if (headerParameters.alg === "ECDH-ES" || headerParameters.alg === "dir") {
        throw new InvalidJoseHeaderError(
          'Cannot use the Key Management Algorithms "ECDH-ES" and "dir" with General JSON Web Encryption Serializations.',
        );
      }

      return {
        header: await header.create(headerParameters),
        recipientUnprotectedHeader: recipient.recipientUnprotectedHeader ?? null,
      };
    }),
  );

  if (new Set(recipients.map((recipient) => recipient.header.parameters.enc)).size > 1) {
    throw new InvalidJoseHeaderError("Cannot have distinct Content Encryption Algorithms.");
  }

  const zipCounts = recipients.filter(
    (recipient) => recipient.header.compressionBackend instanceof CompressionBackend,
  ).length;

  if (zipCounts !== 0 && zipCounts !== recipients.length) {
    throw new InvalidJoseHeaderError("Cannot have distinct Compression Algorithms.");
  }

  return recipients;
}

function validateOptions(options: SerializeOptions, recipients: GeneralJsonWebEncryptionRecipient[]): void {
  if (!Objects.isPlain(options)) {
    throw new TypeError("The provided General JSON Web Encryption Serialize Options is invalid.");
  }

  if (
    "additionalAuthenticatedData" in options &&
    (!Buffer.isBuffer(options.additionalAuthenticatedData) || options.additionalAuthenticatedData.byteLength === 0)
  ) {
    throw new TypeError(
      'The provided General JSON Web Encryption Serialize Option "additionalAuthenticatedData" is invalid.',
    );
  }

  if (
    "jsonWebKeys" in options &&
    (!Array.isArray(options.jsonWebKeys) ||
      options.jsonWebKeys.length === 0 ||
      options.jsonWebKeys.some((jwk) => !(jwk instanceof JsonWebKey)) ||
      options.jsonWebKeys.length !== recipients.length)
  ) {
    throw new TypeError('The provided General JSON Web Encryption Serialize Option "jsonWebKeys" is invalid.');
  }

  if ("detached" in options && typeof options.detached !== "boolean") {
    throw new TypeError('The provided General JSON Web Encryption Serialize Option "detached" is invalid.');
  }
}

/**
 * Serializes the provided JSON Web Encryption Parameters into a General Token.
 *
 * @param plaintext JSON Web Encryption Plaintext.
 * @param headers JSON Web Encryption Headers Parameters.
 * @param options General JSON Web Encryption serialize options.
 * @returns General JSON Web Encryption Token.
 * @throws {InvalidJoseHeaderError} One of the provided JSON Web Encryption Header Parameters is invalid.
 * @throws {InvalidJsonWebEncryptionError} Failed to serialize the General JSON Web Encryption.
 * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to serialize the General JSON Web
 *   Encryption.
 * @throws {TypeError} One of the provided arguments is invalid.
 */
export async function serialize(
  plaintext: Buffer,
  headers: GeneralJsonWebEncryptionHeaders,
  options: SerializeOptions = {},
): Promise<GeneralJsonWebEncryptionToken> {
  validatePlaintext(plaintext);
  const recipients = await validateHeaders(headers);
  validateOptions(options, recipients);

  const joseHeader = recipients[0]!.header;

  const { compressionBackend, contentEncryptionBackend } = joseHeader;

  const contentEncryptionKey = await randomBytesAsync(joseHeader.contentEncryptionBackend.contentEncryptionKeySize);

  const encodedProtectedHeader =
    "protectedHeader" in headers
      ? Buffer.from(JSON.stringify(headers.protectedHeader), "utf8").toString("base64url")
      : "";

  let additionalAuthenticatedData = Buffer.from(encodedProtectedHeader, "ascii");

  if (Buffer.isBuffer(options.additionalAuthenticatedData)) {
    additionalAuthenticatedData = Buffer.concat([
      additionalAuthenticatedData,
      Buffer.from(".", "ascii"),
      Buffer.from(options.additionalAuthenticatedData.toString("base64url"), "ascii"),
    ]);
  }

  if (compressionBackend instanceof CompressionBackend) {
    plaintext = await compressionBackend.compress(plaintext);
  }

  const initializationVector = await contentEncryptionBackend.generateInitializationVector();

  const [ciphertext, authenticationTag] = await contentEncryptionBackend.encrypt(
    plaintext,
    contentEncryptionKey,
    additionalAuthenticatedData,
    initializationVector,
  );

  const tokenRecipients = await Promise.all(
    recipients.map<Promise<GeneralJsonWebEncryptionTokenRecipient>>(async (recipient, index) => {
      const jsonWebKey = options.jsonWebKeys?.[index] ?? recipient.header.jsonWebKey!;

      const encryptedKey = await recipient.header.keyManagementBackend.wrap(
        contentEncryptionKey,
        jsonWebKey,
        recipient.header,
      );

      const recipientParameters: GeneralJsonWebEncryptionTokenRecipient = {
        encrypted_key: encryptedKey.toString("base64url"),
      };

      if (Objects.isPlain(recipient.recipientUnprotectedHeader)) {
        Reflect.set(recipientParameters, "header", recipient.recipientUnprotectedHeader);
      }

      return recipientParameters;
    }),
  );

  const token: GeneralJsonWebEncryptionToken = {
    iv: initializationVector.toString("base64url"),
    recipients: tokenRecipients,
    tag: authenticationTag.toString("base64url"),
  };

  if ("protectedHeader" in headers) {
    Reflect.set(token, "protected", encodedProtectedHeader);
  }

  if ("unprotectedHeader" in headers) {
    Reflect.set(token, "unprotected", headers.unprotectedHeader);
  }

  if (additionalAuthenticatedData.byteLength !== 0) {
    Reflect.set(token, "aad", additionalAuthenticatedData.toString("ascii"));
  }

  if (options.detached !== true) {
    Reflect.set(token, "ciphertext", ciphertext.toString("base64url"));
  }

  return token;
}
