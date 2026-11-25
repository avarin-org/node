import { DigitalSignatureBackend } from "../../jwa/index.js";
import { DIGITAL_SIGNATURE_BACKEND_REGISTRY } from "../../jwa/jws/digital-signature.backend.registry.ts";

/**
 * Registers the provided Digital Signature Backend into the Registry.
 *
 * @param backend Digital Signature Backend to be registered.
 * @throws {TypeError} The provided JSON Web Signature Backend is invalid or is already registered.
 */
export function register(backend: DigitalSignatureBackend): void {
  if (!(backend instanceof DigitalSignatureBackend)) {
    throw new TypeError("The provided JSON Web Signature Backend is invalid.");
  }

  if (DIGITAL_SIGNATURE_BACKEND_REGISTRY.some((entry) => entry.name === backend.name)) {
    throw new TypeError("The provided Digital Signature Backend is already registered.");
  }

  DIGITAL_SIGNATURE_BACKEND_REGISTRY.push(backend);
}
