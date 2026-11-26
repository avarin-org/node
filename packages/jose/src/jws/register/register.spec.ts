import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import { DIGITAL_SIGNATURE_BACKEND_REGISTRY } from "../../jwa/jws/digital-signature.backend.registry.ts";
import { DigitalSignatureBackend } from "../../jwa/jws/digital-signature.backend.ts";
import { RSASSADigitalSignatureBackend } from "../../jwa/jws/rsassa/rsassa.digital-signature.backend.ts";
import type { JsonWebKey } from "../../jwk/jsonwebkey.ts";
import { register } from "./register.ts";

class CustomDigitalSignatureBackend extends DigitalSignatureBackend {
  public constructor() {
    super("custom");
  }
  public async sign(_message: Buffer, _jsonWebKey: JsonWebKey | null): Promise<Buffer> {
    throw new Error("Method not implemented.");
  }
  public async verify(_signature: Buffer, _message: Buffer, _jsonWebKey: JsonWebKey | null): Promise<void> {
    throw new Error("Method not implemented.");
  }
}

class Custom2DigitalSignatureBackend extends DigitalSignatureBackend {
  public constructor() {
    super("custom");
  }
  public async sign(_message: Buffer, _jsonWebKey: JsonWebKey | null): Promise<Buffer> {
    throw new Error("Method not implemented.");
  }
  public async verify(_signature: Buffer, _message: Buffer, _jsonWebKey: JsonWebKey | null): Promise<void> {
    throw new Error("Method not implemented.");
  }
}

const invalidDigitalSignatureBackends: any[] = [
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
  it.each(invalidDigitalSignatureBackends)(
    "should throw when the provided class is not a JSON Web Signature Backend.",
    (backend) => {
      const error = new TypeError("The provided JSON Web Signature Backend is invalid.");
      expect(() => register(backend)).toThrow(error);
    },
  );

  it("should throw when the provided Digital Signature Backend already registered.", () => {
    const error = new TypeError("The provided Digital Signature Backend is already registered.");
    expect(() => register(new RSASSADigitalSignatureBackend("RS256"))).toThrow(error);
  });

  it("should register the provided Digital Signature Backend into the Registry.", () => {
    expect(() => register(new CustomDigitalSignatureBackend())).not.toThrow();
    expect(DIGITAL_SIGNATURE_BACKEND_REGISTRY).toContainEqual(expect.any(CustomDigitalSignatureBackend));
  });

  it.each([CustomDigitalSignatureBackend, Custom2DigitalSignatureBackend])(
    "should throw when the provided Digital Signature is already registered.",
    (Backend) => {
      const error = new TypeError("The provided Digital Signature Backend is already registered.");
      expect(() => register(new Backend())).toThrow(error);
    },
  );
});
