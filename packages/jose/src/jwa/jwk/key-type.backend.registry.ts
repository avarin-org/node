import { EllipticCurveKeyTypeBackend } from "./ec/elliptic-curve.key-type.backend.ts";
import type { KeyTypeBackend } from "./key-type.backend.ts";
import { OctetSequenceKeyTypeBackend } from "./oct/octet-sequence.key-type.backend.ts";
import { RsaKeyTypeBackend } from "./rsa/rsa.key-type.backend.ts";

/**
 * Supported Key Type Backends.
 */
export const KEY_TYPE_BACKEND_REGISTRY: KeyTypeBackend[] = [
  new EllipticCurveKeyTypeBackend(),
  new RsaKeyTypeBackend(),
  new OctetSequenceKeyTypeBackend(),
];
