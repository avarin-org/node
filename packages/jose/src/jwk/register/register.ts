import { KEY_TYPE_BACKEND_REGISTRY } from "../../jwa/jwk/key-type.backend.registry.ts";
import { KeyTypeBackend } from "../../jwa/jwk/key-type.backend.ts";
import type { JsonWebKeyParameters } from "../jsonwebkey.parameters.ts";

/**
 * Registers the provided Key Type Backend into the Registry.
 *
 * @param backend Key Type Backend to be registered.
 * @throws {TypeError} The provided Key Type Backend is invalid or is already registered.
 */
export function register<T extends JsonWebKeyParameters = JsonWebKeyParameters>(backend: KeyTypeBackend<T>): void {
  if (!(backend instanceof KeyTypeBackend)) {
    throw new TypeError("The provided Key Type Backend is invalid.");
  }

  if (KEY_TYPE_BACKEND_REGISTRY.some((entry) => entry.name === backend.name)) {
    throw new TypeError("The provided Key Type Backend is already registered.");
  }

  KEY_TYPE_BACKEND_REGISTRY.push(backend);
}
