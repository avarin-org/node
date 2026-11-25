import { AESCBCContentEncryptionBackend } from "./aescbc/aescbc.content-encryption.backend.ts";
import { AESGCMContentEncryptionBackend } from "./aesgcm/aesgcm.content-encryption.backend.ts";
import type { ContentEncryptionBackend } from "./content-encryption.backend.ts";

/**
 * Supported Content Encryption Backends.
 */
export const CONTENT_ENCRYPTION_BACKEND_REGISTRY: ContentEncryptionBackend[] = [
  new AESCBCContentEncryptionBackend("A128CBC-HS256"),
  new AESCBCContentEncryptionBackend("A192CBC-HS384"),
  new AESCBCContentEncryptionBackend("A256CBC-HS512"),
  new AESGCMContentEncryptionBackend("A128GCM"),
  new AESGCMContentEncryptionBackend("A192GCM"),
  new AESGCMContentEncryptionBackend("A256GCM"),
];
