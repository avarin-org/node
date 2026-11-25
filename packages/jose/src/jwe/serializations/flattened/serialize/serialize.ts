import { Buffer } from "node:buffer";

import { JSON } from "@avarin/primitives/json";
import { Objects } from "@avarin/primitives/objects";

import { CompressionBackend } from "../../../../jwa/jwe/zip/compression.backend.ts";
import { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import { checkPartialJoseHeader } from "../../../../utils/check-partial-jose-header/check-partial-jose-header.ts";
import { header } from "../../../header/index.ts";
import type { JsonWebEncryptionHeaderParameters } from "../../../header/jsonwebencryption.header.parameters.ts";
import type { JsonWebEncryptionHeader } from "../../../header/jsonwebencryption.header.ts";
import type { FlattenedJsonWebEncryptionHeaders } from "../flattened.jsonwebencryption.headers.ts";
import type { FlattenedJsonWebEncryptionToken } from "../flattened.jsonwebencryption.token.ts";
import type { SerializeOptions } from "./serialize.options.ts";

function validatePlaintext(plaintext: Buffer): void {
  if (!Buffer.isBuffer(plaintext) || plaintext.byteLength === 0) {
    throw new TypeError("The provided Plaintext is invalid.");
  }
}

async function validateHeaders(headers: FlattenedJsonWebEncryptionHeaders): Promise<JsonWebEncryptionHeader> {
  if (!Objects.isPlain(headers)) {
    throw new TypeError("The provided JSON Web Encryption Headers is invalid.");
  }

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
    "recipientUnprotectedHeader" in headers &&
    (!Objects.isPlain(headers.recipientUnprotectedHeader) ||
      !checkPartialJoseHeader(headers.recipientUnprotectedHeader))
  ) {
    throw new TypeError("The provided JSON Web Encryption Recipient Unprotected Header is invalid.");
  }

  if (
    !("protectedHeader" in headers) &&
    !("unprotectedHeader" in headers) &&
    !("recipientUnprotectedHeader" in headers)
  ) {
    throw new TypeError("Missing at least one required JSON Web Encryption Header.");
  }

  const headerKeys = [
    ...Object.keys(headers.protectedHeader ?? {}),
    ...Object.keys(headers.unprotectedHeader ?? {}),
    ...Object.keys(headers.recipientUnprotectedHeader ?? {}),
  ];

  if (headerKeys.length !== new Set(headerKeys).size) {
    throw new TypeError("Cannot have repeated JSON Web Encryption Header Parameters.");
  }

  const headerParameters = {
    ...headers.protectedHeader,
    ...headers.unprotectedHeader,
    ...headers.recipientUnprotectedHeader,
  } as JsonWebEncryptionHeaderParameters;

  return await header.create(headerParameters);
}

function validateOptions(options: SerializeOptions): void {
  if (!Objects.isPlain(options)) {
    throw new TypeError("The provided Flattened JSON Web Encryption Serialize Options is invalid.");
  }

  if (
    "additionalAuthenticatedData" in options &&
    (!Buffer.isBuffer(options.additionalAuthenticatedData) || options.additionalAuthenticatedData.byteLength === 0)
  ) {
    throw new TypeError(
      'The provided Flattened JSON Web Encryption Serialize Option "additionalAuthenticatedData" is invalid.',
    );
  }

  if ("jsonWebKey" in options && options.jsonWebKey !== null && !(options.jsonWebKey instanceof JsonWebKey)) {
    throw new TypeError('The provided Flattened JSON Web Encryption Serialize Option "jsonWebKey" is invalid.');
  }

  if ("detached" in options && typeof options.detached !== "boolean") {
    throw new TypeError('The provided Flattened JSON Web Encryption Serialize Option "detached" is invalid.');
  }
}

/**
 * Serializes the provided JSON Web Encryption Parameters into a Flattened Token.
 *
 * @param plaintext JSON Web Encryption Plaintext.
 * @param headers JSON Web Encryption Headers Parameters.
 * @param options Flattened JSON Web Encryption serialize options.
 * @returns Flattened JSON Web Encryption Token.
 * @throws {InvalidJoseHeaderError} One of the provided JSON Web Encryption Header Parameters is invalid.
 * @throws {InvalidJsonWebEncryptionError} Failed to serialize the Flattened JSON Web Encryption.
 * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to serialize the Flattened JSON Web
 *   Encryption.
 * @throws {TypeError} One of the provided arguments is invalid.
 */
export async function serialize(
  plaintext: Buffer,
  headers: FlattenedJsonWebEncryptionHeaders,
  options: SerializeOptions = {},
): Promise<FlattenedJsonWebEncryptionToken> {
  validatePlaintext(plaintext);
  const joseHeader = await validateHeaders(headers);
  validateOptions(options);

  const { compressionBackend, contentEncryptionBackend, keyManagementBackend } = joseHeader;

  const jsonWebKey = options.jsonWebKey ?? joseHeader.jsonWebKey!;

  const contentEncryptionKey = await keyManagementBackend.generateContentEncryptionKey(jsonWebKey, joseHeader);
  const encryptedKey = await keyManagementBackend.wrap(contentEncryptionKey, jsonWebKey, joseHeader);

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

  const token: FlattenedJsonWebEncryptionToken = {
    encrypted_key: encryptedKey.toString("base64url"),
    iv: initializationVector.toString("base64url"),
    tag: authenticationTag.toString("base64url"),
  };

  if ("protectedHeader" in headers) {
    Reflect.set(token, "protected", encodedProtectedHeader);
  }

  if ("unprotectedHeader" in headers) {
    Reflect.set(token, "unprotected", headers.unprotectedHeader);
  }

  if ("recipientUnprotectedHeader" in headers) {
    Reflect.set(token, "header", headers.recipientUnprotectedHeader);
  }

  if (additionalAuthenticatedData.byteLength !== 0) {
    Reflect.set(token, "aad", additionalAuthenticatedData.toString("ascii"));
  }

  if (options.detached !== true) {
    Reflect.set(token, "ciphertext", ciphertext.toString("base64url"));
  }

  return token;
}
