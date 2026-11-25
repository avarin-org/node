import { Buffer } from "node:buffer";

import { JSON } from "@avarin/primitives/json";
import { Objects } from "@avarin/primitives/objects";

import { CompressionBackend } from "../../../../jwa/jwe/zip/compression.backend.ts";
import { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import { header } from "../../../header/index.ts";
import type { JsonWebEncryptionHeaderParameters } from "../../../header/jsonwebencryption.header.parameters.ts";
import type { SerializeOptions } from "./serialize.options.ts";

function validatePlaintext(plaintext: Buffer): void {
  if (!Buffer.isBuffer(plaintext) || plaintext.byteLength === 0) {
    throw new TypeError("The provided Plaintext is invalid.");
  }
}

function validateProtectedHeader(protectedHeader: JsonWebEncryptionHeaderParameters): void {
  if (!header.check(protectedHeader)) {
    throw new TypeError("The provided JSON Web Encryption Protected Header is invalid.");
  }
}

function validateOptions(options: SerializeOptions): void {
  if (!Objects.isPlain(options)) {
    throw new TypeError("The provided Compact JSON Web Encryption Serialize Options is invalid.");
  }

  if ("jsonWebKey" in options && !(options.jsonWebKey instanceof JsonWebKey)) {
    throw new TypeError('The provided Compact JSON Web Encryption Serialize Option "jsonWebKey" is invalid.');
  }

  if ("detached" in options && typeof options.detached !== "boolean") {
    throw new TypeError('The provided Compact JSON Web Encryption Serialize Option "detached" is invalid.');
  }
}

/**
 * Serializes the provided JSON Web Encryption Parameters into a Compact Token.
 *
 * @param plaintext JSON Web Encryption Plaintext.
 * @param protectedHeaderParameters JSON Web Encryption Protected Header Parameters.
 * @param options Compact JSON Web Encryption serialize options.
 * @returns Compact JSON Web Encryption Token.
 * @throws {InvalidJoseHeaderError} The provided JSON Web Encryption Protected Header Parameters is invalid.
 * @throws {InvalidJsonWebEncryptionError} Failed to serialize the Compact JSON Web Encryption.
 * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to serialize the Compact JSON Web
 *   Encryption.
 * @throws {TypeError} One of the provided arguments is invalid.
 */
export async function serialize(
  plaintext: Buffer,
  protectedHeaderParameters: JsonWebEncryptionHeaderParameters,
  options: SerializeOptions = {},
): Promise<string> {
  validatePlaintext(plaintext);
  validateProtectedHeader(protectedHeaderParameters);
  validateOptions(options);

  const protectedHeader = await header.create(protectedHeaderParameters);

  const { compressionBackend, contentEncryptionBackend, keyManagementBackend, parameters } = protectedHeader;

  const jsonWebKey = options.jsonWebKey ?? protectedHeader.jsonWebKey!;

  const contentEncryptionKey = await keyManagementBackend.generateContentEncryptionKey(jsonWebKey, protectedHeader);
  const encryptedKey = await keyManagementBackend.wrap(contentEncryptionKey, jsonWebKey, protectedHeader);

  const encodedProtectedHeader = Buffer.from(JSON.stringify(parameters), "utf8").toString("base64url");
  const additionalAuthenticatedData = Buffer.from(encodedProtectedHeader, "ascii");

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

  const encodedEncryptedKey = encryptedKey.toString("base64url");
  const encodedInitializationVector = initializationVector.toString("base64url");
  const encodedCiphertext = ciphertext.toString("base64url");
  const encodedAuthenticationTag = authenticationTag.toString("base64url");

  return [
    encodedProtectedHeader,
    encodedEncryptedKey,
    encodedInitializationVector,
    options.detached === true ? "" : encodedCiphertext,
    encodedAuthenticationTag,
  ].join(".");
}
