import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import { InvalidJoseHeaderError } from "../../errors/invalid-jose-header.error.ts";
import { DigitalSignatureBackend } from "../../jwa/index.ts";
import { DIGITAL_SIGNATURE_BACKEND_REGISTRY } from "../../jwa/jws/digital-signature.backend.registry.ts";
import type { JsonWebSignatureHeaderParameters } from "./jsonwebsignature.header.parameters.ts";
import { JsonWebSignatureHeader } from "./jsonwebsignature.header.ts";

const invalidDigitalSignatureAlgorithms: any[] = [
  undefined,
  null,
  true,
  1,
  1.2,
  1n,
  Symbol("a"),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  {},
  [],
  "a",
];

describe("JSON Web Signature Header", () => {
  const parameters: JsonWebSignatureHeaderParameters = { alg: "ES256" };

  describe("constructor", () => {
    it.each(invalidDigitalSignatureAlgorithms)(
      'should throw when the provided JOSE Header Parameter "alg" is invalid.',
      (alg) => {
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "alg".');
        expect(() => new JsonWebSignatureHeader({ ...parameters, alg })).toThrow(error);
      },
    );

    it.each(DIGITAL_SIGNATURE_BACKEND_REGISTRY.map((backend) => backend.name))(
      "should return a JSON Web Signature Header.",
      (alg) => {
        let header!: JsonWebSignatureHeader;

        expect(() => (header = new JsonWebSignatureHeader({ alg }))).not.toThrow();

        expect(header.digitalSignatureBackend).toBeInstanceOf(DigitalSignatureBackend);
        expect(header.digitalSignatureBackend.name).toBe(alg);

        expect(header.certificateChain).toBeNull();
        expect(header.jsonWebKey).toBeNull();
        expect(header.parameters).toStrictEqual<Partial<JsonWebSignatureHeaderParameters>>({ alg });
      },
    );
  });
});
