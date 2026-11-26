import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import { InvalidJoseHeaderError } from "../../errors/invalid-jose-header.error.ts";
import { DIGITAL_SIGNATURE_BACKEND_REGISTRY } from "../../jwa/jws/digital-signature.backend.registry.ts";
import { DigitalSignatureBackend } from "../../jwa/jws/digital-signature.backend.ts";
import type { JsonWebSignatureHeaderParameters } from "./jsonwebsignature.header.parameters.ts";
import { JsonWebSignatureHeader } from "./jsonwebsignature.header.ts";

const invalidAlgs: any[] = [
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

const invalidB64s: any[] = [undefined, null, 1, 1.2, 1n, "a", Symbol("a"), Buffer, Buffer.alloc(1), () => 1, {}, []];

describe("JSON Web Signature Header", () => {
  const parameters: JsonWebSignatureHeaderParameters = { alg: "ES256" };

  describe("constructor", () => {
    it.each(invalidAlgs)('should throw when the provided JOSE Header Parameter "alg" is invalid.', (alg) => {
      const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "alg".');
      expect(() => new JsonWebSignatureHeader({ ...parameters, alg })).toThrow(error);
    });

    it.each(invalidB64s)('should throw when the provided JOSE Header Parameter "b64" is invalid.', (b64) => {
      const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "b64".');
      expect(() => new JsonWebSignatureHeader({ ...parameters, b64 })).toThrow(error);
    });

    it('should throw when the JOSE Header Parameter "b64" is not present at the JOSE Header Parameter "crit".', () => {
      const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "b64".');
      expect(() => new JsonWebSignatureHeader({ ...parameters, b64: false })).toThrow(error);
    });

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

    it.each(DIGITAL_SIGNATURE_BACKEND_REGISTRY.map((backend) => backend.name))(
      'should return a JSON Web Signature Header with the "b64" extension.',
      (alg) => {
        let header!: JsonWebSignatureHeader;

        expect(() => (header = new JsonWebSignatureHeader({ alg, b64: false, crit: ["b64"] }))).not.toThrow();

        expect(header.digitalSignatureBackend).toBeInstanceOf(DigitalSignatureBackend);
        expect(header.digitalSignatureBackend.name).toBe(alg);

        expect(header.certificateChain).toBeNull();
        expect(header.jsonWebKey).toBeNull();
        expect(header.parameters).toStrictEqual<Partial<JsonWebSignatureHeaderParameters>>({
          alg,
          b64: false,
          crit: ["b64"],
        });
      },
    );
  });
});
