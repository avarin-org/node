import type { JsonWebKeyParameters } from "../../jwk/jsonwebkey.parameters.ts";
import { EllipticCurveJsonWebKeyBackend } from "./ec/elliptic-curve.jsonwebkey.backend.ts";
import type { JsonWebKeyBackend } from "./jsonwebkey.backend.ts";
import { OctetSequenceJsonWebKeyBackend } from "./oct/octet-sequence.jsonwebkey.backend.ts";
import { RsaJsonWebKeyBackend } from "./rsa/rsa.jsonwebkey.backend.ts";

/**
 * Supported JSON Web Key Backends.
 */
export const JSONWEBKEY_BACKEND_REGISTRY: (typeof JsonWebKeyBackend<JsonWebKeyParameters>)[] = [
  EllipticCurveJsonWebKeyBackend,
  RsaJsonWebKeyBackend,
  OctetSequenceJsonWebKeyBackend,
];
