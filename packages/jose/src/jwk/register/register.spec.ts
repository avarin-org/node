import { Buffer } from "node:buffer";
import type { KeyObject } from "node:crypto";

import { describe, expect, it } from "vitest";

import { KEY_TYPE_BACKEND_REGISTRY } from "../../jwa/jwk/key-type.backend.registry.ts";
import { KeyTypeBackend } from "../../jwa/jwk/key-type.backend.ts";
import type { KeyType } from "../../jwa/jwk/key-type.type.ts";
import { RsaKeyTypeBackend } from "../../jwa/jwk/rsa/rsa.key-type.backend.ts";
import type { JsonWebKeyParameters } from "../jsonwebkey.parameters.ts";
import type { JsonWebKey } from "../jsonwebkey.ts";
import { register } from "./register.ts";

class CustomJsonWebKeyBackend extends KeyTypeBackend {
  public override readonly name: KeyType = "custom";
  public async generate(
    _options: NodeJS.Dict<unknown>,
    _parameters?: Partial<JsonWebKeyParameters>,
  ): Promise<JsonWebKey> {
    throw new Error("Method not implemented.");
  }
  public getCryptoKey(_parameters: JsonWebKeyParameters): KeyObject {
    throw new Error("Method not implemented.");
  }
  public getPrivateParameters(): string[] {
    throw new Error("Method not implemented.");
  }
}

class Custom2JsonWebKeyBackend extends KeyTypeBackend {
  public override readonly name: KeyType = "custom";
  public async generate(
    _options: NodeJS.Dict<unknown>,
    _parameters?: Partial<JsonWebKeyParameters>,
  ): Promise<JsonWebKey> {
    throw new Error("Method not implemented.");
  }
  public getCryptoKey(_parameters: JsonWebKeyParameters): KeyObject {
    throw new Error("Method not implemented.");
  }
  public getPrivateParameters(): string[] {
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
  it.each(invalidJsonWebKeyBackends)("should throw when the provided class is not a Key Type Backend.", (backend) => {
    const error = new TypeError("The provided Key Type Backend is invalid.");
    expect(() => register(backend)).toThrow(error);
  });

  it("should throw when the provided Key Type Backend already registered.", () => {
    const error = new TypeError("The provided Key Type Backend is already registered.");
    expect(() => register(new RsaKeyTypeBackend())).toThrow(error);
  });

  it("should register the provided Key Type Backend into the Registry.", () => {
    expect(() => register(new CustomJsonWebKeyBackend())).not.toThrow();
    expect(KEY_TYPE_BACKEND_REGISTRY).toContainEqual(expect.any(CustomJsonWebKeyBackend));
  });

  it.each([CustomJsonWebKeyBackend, Custom2JsonWebKeyBackend])(
    "should throw when the provided JSON Web Key Key Type is already registered.",
    (Backend) => {
      const error = new TypeError("The provided Key Type Backend is already registered.");
      expect(() => register(new Backend())).toThrow(error);
    },
  );
});
