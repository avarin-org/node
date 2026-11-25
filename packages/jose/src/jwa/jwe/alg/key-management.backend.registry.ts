import { AESGCMKWKeyManagementBackend } from "./aesgcmkw/aesgcmkw.key-management.backend.ts";
import { AESKWKeyManagementBackend } from "./aeskw/aeskw.key-management.backend.ts";
import { DirKeyManagementBackend } from "./dir/dir.key-management.backend.ts";
import { ECDHESKeyManagementBackend } from "./ecdhes/ecdhes.key-management.backend.ts";
import type { KeyManagementBackend } from "./key-management.backend.ts";
import { PBES2KeyManagementBackend } from "./pbes2/pbes2.key-management.backend.ts";
import { RSAESKeyManagementBackend } from "./rsaes/rsaes.key-management.backend.ts";

/**
 * Supported Key Management Backends.
 */
export const KEY_MANAGEMENT_BACKEND_REGISTRY: KeyManagementBackend[] = [
  new AESGCMKWKeyManagementBackend("A128GCMKW"),
  new AESGCMKWKeyManagementBackend("A192GCMKW"),
  new AESGCMKWKeyManagementBackend("A256GCMKW"),
  new AESKWKeyManagementBackend("A128KW"),
  new AESKWKeyManagementBackend("A192KW"),
  new AESKWKeyManagementBackend("A256KW"),
  new DirKeyManagementBackend(),
  new ECDHESKeyManagementBackend("ECDH-ES"),
  new ECDHESKeyManagementBackend("ECDH-ES+A128KW"),
  new ECDHESKeyManagementBackend("ECDH-ES+A192KW"),
  new ECDHESKeyManagementBackend("ECDH-ES+A256KW"),
  new PBES2KeyManagementBackend("PBES2-HS256+A128KW"),
  new PBES2KeyManagementBackend("PBES2-HS384+A192KW"),
  new PBES2KeyManagementBackend("PBES2-HS512+A256KW"),
  new RSAESKeyManagementBackend("RSA-OAEP"),
  new RSAESKeyManagementBackend("RSA-OAEP-256"),
  new RSAESKeyManagementBackend("RSA-OAEP-384"),
  new RSAESKeyManagementBackend("RSA-OAEP-512"),
  new RSAESKeyManagementBackend("RSA1_5"),
];
