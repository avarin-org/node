import { Buffer } from "node:buffer";
import type { KeyObject } from "node:crypto";

import { describe, expect, it } from "vitest";

import { JSONWEBKEY_BACKEND_REGISTRY } from "../../jwa/jwk/jsonwebkey.backend.registry.ts";
import { JsonWebKeyBackend } from "../../jwa/jwk/jsonwebkey.backend.ts";
import type { KeyType } from "../../jwa/jwk/key-type.type.ts";
import { RsaJsonWebKeyBackend } from "../../jwa/jwk/rsa/rsa.jsonwebkey.backend.ts";
import type { JsonWebKeyParameters } from "../jsonwebkey.parameters.ts";
import { register } from "./register.ts";

class CustomJsonWebKeyBackend extends JsonWebKeyBackend {
  public static override readonly keyType: KeyType = "custom";
  public override getCryptoKey(): KeyObject {
    throw new Error("Method not implemented.");
  }
  public override toJSON(): JsonWebKeyParameters {
    throw new Error("Method not implemented.");
  }
}

class Custom2JsonWebKeyBackend extends JsonWebKeyBackend {
  public static override readonly keyType: KeyType = "custom";
  public override getCryptoKey(): KeyObject {
    throw new Error("Method not implemented.");
  }
  public override toJSON(): JsonWebKeyParameters {
    throw new Error("Method not implemented.");
  }
}

const invalidJsonWebKeyBackends: any[] = [
  undefined,
  null,
  true,
  1,
  1.2,
  1n,
  "",
  Symbol("a"),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  {},
  [],
];

describe("register()", () => {
  it.each(invalidJsonWebKeyBackends)(
    "should throw when the provided class is not a JSON Web Key Backend.",
    (backend) => {
      const error = new TypeError("The provided JSON Web Key Backend is invalid.");
      expect(() => register(backend)).toThrow(error);
    },
  );

  it("should throw when the provided JSON Web Key Backend already registered.", () => {
    const error = new TypeError("The provided JSON Web Key Backend is already registered.");
    expect(() => register(RsaJsonWebKeyBackend)).toThrow(error);
  });

  it("should register the provided JSON Web Key Backend into the Registry.", () => {
    expect(() => register(CustomJsonWebKeyBackend)).not.toThrow();
    expect(JSONWEBKEY_BACKEND_REGISTRY).toContain(CustomJsonWebKeyBackend);
  });

  it("should throw when the provided JSON Web Key Key Type is already registered.", () => {
    const error = new TypeError("The provided JSON Web Key Backend is already registered.");
    expect(() => register(Custom2JsonWebKeyBackend)).toThrow(error);
  });
});
