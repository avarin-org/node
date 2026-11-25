import { KEY_MANAGEMENT_BACKEND_REGISTRY } from "../../jwa/jwe/alg/key-management.backend.registry.ts";
import { KeyManagementBackend } from "../../jwa/jwe/alg/key-management.backend.ts";
import { ContentEncryptionBackend } from "../../jwa/jwe/enc/content-encryption.backend.js";
import { CONTENT_ENCRYPTION_BACKEND_REGISTRY } from "../../jwa/jwe/enc/content-encryption.backend.registry.ts";
import { CompressionBackend } from "../../jwa/jwe/zip/compression.backend.js";
import { COMPRESSION_BACKEND_REGISTRY } from "../../jwa/jwe/zip/compression.backend.registry.ts";

/**
 * Registers the provided Key Management Backend into the Registry.
 *
 * @param backend Key Management Backend to be registered.
 * @throws {TypeError} The provided Key Management Backend is invalid or is already registered.
 */
export function register(backend: KeyManagementBackend): void;

/**
 * Registers the provided Content Encryption Backend into the Registry.
 *
 * @param backend Content Encryption Backend to be registered.
 * @throws {TypeError} The provided Content Encryption Backend is invalid or is already registered.
 */
export function register(backend: ContentEncryptionBackend): void;

/**
 * Registers the provided Compression Backend into the Registry.
 *
 * @param backend Compression Backend to be registered.
 * @throws {TypeError} The provided Compression Backend is invalid or is already registered.
 */
export function register(backend: CompressionBackend): void;

/**
 * Registers the provided JSON Web Encryption Backend into the Registry.
 *
 * @param backend JSON Web Encryption Backend to be registered.
 * @throws {TypeError} The provided JSON Web Encryption Backend is invalid or is already registered.
 */
export function register(backend: KeyManagementBackend | ContentEncryptionBackend | CompressionBackend): void {
  if (
    !(backend instanceof KeyManagementBackend) &&
    !(backend instanceof ContentEncryptionBackend) &&
    !(backend instanceof CompressionBackend)
  ) {
    throw new TypeError("The provided JSON Web Encryption Backend is invalid.");
  }

  switch (true) {
    case backend instanceof KeyManagementBackend: {
      if (KEY_MANAGEMENT_BACKEND_REGISTRY.some((entry) => entry.name === backend.name)) {
        throw new TypeError("The provided Key Management Backend is already registered.");
      }

      KEY_MANAGEMENT_BACKEND_REGISTRY.push(backend);
      break;
    }

    case backend instanceof ContentEncryptionBackend: {
      if (CONTENT_ENCRYPTION_BACKEND_REGISTRY.some((entry) => entry.name === backend.name)) {
        throw new TypeError("The provided Content Encryption Backend is already registered.");
      }

      CONTENT_ENCRYPTION_BACKEND_REGISTRY.push(backend);
      break;
    }

    case backend instanceof CompressionBackend: {
      if (COMPRESSION_BACKEND_REGISTRY.some((entry) => entry.name === backend.name)) {
        throw new TypeError("The provided Compression Backend is already registered.");
      }

      COMPRESSION_BACKEND_REGISTRY.push(backend);
      break;
    }

    /* istanbul ignore next */
    default: {
      break;
    }
  }
}
