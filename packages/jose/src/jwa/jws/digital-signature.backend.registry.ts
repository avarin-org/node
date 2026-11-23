import type { DigitalSignatureBackend } from "./digital-signature.backend.ts";
import { ECDSADigitalSignatureBackend } from "./ecdsa/ecdsa.digital-signature.backend.ts";
import { HMACDigitalSignatureBackend } from "./hmac/hmac.digital-signature.backend.ts";
import { NoneDigitalSignatureBackend } from "./none/none.digital-signature.backend.ts";
import { RSASSADigitalSignatureBackend } from "./rsassa/rsassa.digital-signature.backend.ts";

/**
 * Supported Digital Signature Backends.
 */
export const DIGITAL_SIGNATURE_BACKEND_REGISTRY: DigitalSignatureBackend[] = [
  new ECDSADigitalSignatureBackend("ES256"),
  new ECDSADigitalSignatureBackend("ES384"),
  new ECDSADigitalSignatureBackend("ES512"),
  new HMACDigitalSignatureBackend("HS256"),
  new HMACDigitalSignatureBackend("HS384"),
  new HMACDigitalSignatureBackend("HS512"),
  new NoneDigitalSignatureBackend(),
  new RSASSADigitalSignatureBackend("PS256"),
  new RSASSADigitalSignatureBackend("PS384"),
  new RSASSADigitalSignatureBackend("PS512"),
  new RSASSADigitalSignatureBackend("RS256"),
  new RSASSADigitalSignatureBackend("RS384"),
  new RSASSADigitalSignatureBackend("RS512"),
];
