import { Functions } from "@avarin/primitives/functions";
import { Strings } from "@avarin/primitives/strings";

import { JSONWEBKEY_BACKEND_REGISTRY } from "../../jwa/jwk/jsonwebkey.backend.registry.ts";
import { JsonWebKeyBackend } from "../../jwa/jwk/jsonwebkey.backend.ts";
import type { JsonWebKeyParameters } from "../jsonwebkey.parameters.ts";

/**
 * Registers the provided JSON Web Key Backend into the Registry.
 *
 * @param backend JSON Web Key Backend to be registered.
 * @throws {TypeError} The provided JSON Web Key Backend is invalid or is already registered.
 */
export function register<T extends JsonWebKeyParameters = JsonWebKeyParameters>(
  backend: typeof JsonWebKeyBackend<T>,
): void {
  if (
    !Functions.isClass(backend) ||
    !(backend.prototype instanceof JsonWebKeyBackend) ||
    !Strings.isNonEmpty(backend.keyType)
  ) {
    throw new TypeError("The provided JSON Web Key Backend is invalid.");
  }

  if (JSONWEBKEY_BACKEND_REGISTRY.some((entry) => entry === backend || entry.keyType === backend.keyType)) {
    throw new TypeError("The provided JSON Web Key Backend is already registered.");
  }

  JSONWEBKEY_BACKEND_REGISTRY.push(backend);
}
