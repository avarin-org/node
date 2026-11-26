import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import { InvalidJsonWebTokenClaimsError } from "../../errors/invalid-jsonwebtoken-claims.error.ts";
import type { JsonWebTokenClaimsParameters } from "./jsonwebtoken.claims.parameters.ts";
import { JsonWebTokenClaims } from "./jsonwebtoken.claims.ts";

const invalidOptions: any[] = [null, true, 1, 1.2, 1n, "a", Symbol("a"), Buffer, Buffer.alloc(1), () => 1, []];

const invalidIgnoreExpireds: any[] = [
  undefined,
  null,
  1,
  1.2,
  1n,
  "a",
  Symbol("a"),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  {},
  [],
];

const invalidValidationOptions: any[] = [
  undefined,
  null,
  true,
  1,
  1.2,
  1n,
  "a",
  Symbol("a"),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  [],
];

const invalidEssentialValidationOptions: any[] = [
  undefined,
  null,
  1,
  1.2,
  1n,
  "a",
  Symbol("a"),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  {},
  [],
];

const invalidValuesValidationOptions: any[] = [
  undefined,
  null,
  true,
  1,
  1.2,
  1n,
  "a",
  Symbol("a"),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  {},
  [],
];

const invalidParameters: any[] = [
  undefined,
  null,
  true,
  1,
  1.2,
  1n,
  "a",
  Symbol("a"),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  [],
];

const invalidIssuers: any[] = [
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
  "",
];

const invalidSubjects: any[] = [
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
  "",
];

const invalidAudiences: any[] = [
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
  "",
  [],
  [undefined],
  [null],
  [true],
  [1],
  [1.2],
  [1n],
  [Symbol("a")],
  [Buffer],
  [Buffer.alloc(1)],
  [() => 1],
  [{}],
  [[]],
  [""],
  ["audience", "audience"],
];

const invalidExpiresAts: any[] = [
  undefined,
  null,
  true,
  1n,
  "a",
  Symbol("a"),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  {},
  [],
  1.2,
  1,
];

const invalidNotBefores: any[] = [
  undefined,
  null,
  true,
  1n,
  "a",
  Symbol("a"),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  {},
  [],
  1.2,
  Date.now(),
];

const invalidIssuedAts: any[] = [
  undefined,
  null,
  true,
  1n,
  "a",
  Symbol("a"),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  {},
  [],
  1.2,
];

const invalidJsonWebTokenIDs: any[] = [
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
  "",
];

describe("JSON Web Token Claims", () => {
  describe("constructor", () => {
    it.each(invalidOptions)("should throw when the provided JSON Web Token Claims Options is invalid.", (options) => {
      const error = new TypeError("The provided JSON Web Token Claims Options is invalid.");
      expect(() => new JsonWebTokenClaims({}, options)).toThrow(error);
    });

    it.each(invalidIgnoreExpireds)(
      'should throw when the provided JSON Web Token Claims Option "ignoreExpired" is invalid.',
      (ignoreExpired) => {
        const error = new TypeError('The provided JSON Web Token Claims Option "ignoreExpired" is invalid.');
        expect(() => new JsonWebTokenClaims({}, { ignoreExpired })).toThrow(error);
      },
    );

    it.each(invalidValidationOptions)(
      'should throw when the provided JSON Web Token Claims Option "validationOptions" is invalid.',
      (validationOptions) => {
        const error = new TypeError('The provided JSON Web Token Claims Option "validationOptions" is invalid.');
        expect(() => new JsonWebTokenClaims({}, { validationOptions })).toThrow(error);
      },
    );

    it.each(invalidEssentialValidationOptions)(
      'should throw when the provided JSON Web Token Claim Validation Option "essential" is invalid.',
      (essential) => {
        const error = new TypeError('The provided JSON Web Token Claim Validation Option "essential" is invalid.');
        expect(() => new JsonWebTokenClaims({}, { validationOptions: { iss: { essential } } })).toThrow(error);
      },
    );

    it('should throw when the providing both "value" and "values" JSON Web Token Claim Validation Options.', () => {
      const error = new TypeError('Cannot have both "value" and "values" JSON Web Token Claim Validation Options.');

      expect(() => new JsonWebTokenClaims({}, { validationOptions: { iss: { value: "", values: [""] } } })).toThrow(
        error,
      );
    });

    it.each(invalidValuesValidationOptions)(
      'should throw when the provided JSON Web Token Claim Validation Option "values" is invalid.',
      (values) => {
        const error = new TypeError('The provided JSON Web Token Claim Validation Option "values" is invalid.');
        expect(() => new JsonWebTokenClaims({}, { validationOptions: { iss: { values } } })).toThrow(error);
      },
    );

    it.each(invalidParameters)(
      "should throw when the provided JSON Web Token Claims Parameters is invalid.",
      (parameters) => {
        const error = new TypeError("The provided JSON Web Token Claims Parameters is invalid.");
        expect(() => new JsonWebTokenClaims(parameters)).toThrow(error);
      },
    );

    it.each(invalidIssuers)('should throw when the provided JSON Web Token Claim "iss" is invalid.', (iss) => {
      const error = new InvalidJsonWebTokenClaimsError('Invalid JSON Web Token Claim "iss".');
      expect(() => new JsonWebTokenClaims({ iss })).toThrow(error);
    });

    it.each(invalidSubjects)('should throw when the provided JSON Web Token Claim "sub" is invalid.', (sub) => {
      const error = new InvalidJsonWebTokenClaimsError('Invalid JSON Web Token Claim "sub".');
      expect(() => new JsonWebTokenClaims({ sub })).toThrow(error);
    });

    it.each(invalidAudiences)('should throw when the provided JSON Web Token Claim "aud" is invalid.', (aud) => {
      const error = new InvalidJsonWebTokenClaimsError('Invalid JSON Web Token Claim "aud".');
      expect(() => new JsonWebTokenClaims({ aud })).toThrow(error);
    });

    it.each(invalidExpiresAts)('should throw when the provided JSON Web Token Claim "exp" is invalid.', (exp) => {
      const error = new InvalidJsonWebTokenClaimsError('Invalid JSON Web Token Claim "exp".');
      expect(() => new JsonWebTokenClaims({ exp })).toThrow(error);
    });

    it.each(invalidNotBefores)('should throw when the provided JSON Web Token Claim "nbf" is invalid.', (nbf) => {
      const error = new InvalidJsonWebTokenClaimsError('Invalid JSON Web Token Claim "nbf".');
      expect(() => new JsonWebTokenClaims({ nbf })).toThrow(error);
    });

    it.each(invalidIssuedAts)('should throw when the provided JSON Web Token Claim "iat" is invalid.', (iat) => {
      const error = new InvalidJsonWebTokenClaimsError('Invalid JSON Web Token Claim "iat".');
      expect(() => new JsonWebTokenClaims({ iat })).toThrow(error);
    });

    it.each(invalidJsonWebTokenIDs)('should throw when the provided JSON Web Token Claim "jti" is invalid.', (jti) => {
      const error = new InvalidJsonWebTokenClaimsError('Invalid JSON Web Token Claim "jti".');
      expect(() => new JsonWebTokenClaims({ jti })).toThrow(error);
    });

    it("should throw when not providing an essential JSON Web Token Claim.", () => {
      const error = new InvalidJsonWebTokenClaimsError('Missing required JSON Web Token Claim "iss".');
      expect(() => new JsonWebTokenClaims({}, { validationOptions: { iss: { essential: true } } })).toThrow(error);
    });

    it("should throw when a provided JSON Web Token Claim does not match its expected value.", () => {
      const error = new InvalidJsonWebTokenClaimsError('Unexpected value for JSON Web Token Claim "iss".');

      expect(
        () =>
          new JsonWebTokenClaims(
            { iss: "https://issuer.example.com" },
            { validationOptions: { iss: { value: "https://issuer.example.org" } } },
          ),
      ).toThrow(error);
    });

    it("should throw when a provided JSON Web Token Claim does not match one of its expected values.", () => {
      const error = new InvalidJsonWebTokenClaimsError('Unexpected value for JSON Web Token Claim "iss".');

      expect(
        () =>
          new JsonWebTokenClaims(
            { iss: "https://issuer.example.com" },
            { validationOptions: { iss: { values: ["https://issuer.example.org", "https://issuer.example.net"] } } },
          ),
      ).toThrow(error);
    });

    it("should return a JSON Web Token Claims with an Issuer.", () => {
      let claims!: JsonWebTokenClaims;

      expect(() => (claims = new JsonWebTokenClaims({ iss: "https://issuer.example.com" }))).not.toThrow();
      expect(claims.parameters).toStrictEqual<JsonWebTokenClaimsParameters>({ iss: "https://issuer.example.com" });
    });

    it("should return a JSON Web Token Claims with a Subject.", () => {
      let claims!: JsonWebTokenClaims;

      expect(() => (claims = new JsonWebTokenClaims({ sub: "https://subject.example.com" }))).not.toThrow();
      expect(claims.parameters).toStrictEqual<JsonWebTokenClaimsParameters>({ sub: "https://subject.example.com" });
    });

    it("should return a JSON Web Token Claims with a single Audience.", () => {
      let claims!: JsonWebTokenClaims;

      expect(() => (claims = new JsonWebTokenClaims({ aud: "https://audience.example.com" }))).not.toThrow();
      expect(claims.parameters).toStrictEqual<JsonWebTokenClaimsParameters>({ aud: "https://audience.example.com" });
    });

    it("should return a JSON Web Token Claims with multiple Audiences.", () => {
      let claims!: JsonWebTokenClaims;

      expect(
        () =>
          (claims = new JsonWebTokenClaims({
            aud: ["https://audience.example.com", "https://audience.example.net"],
          })),
      ).not.toThrow();

      expect(claims.parameters).toStrictEqual<JsonWebTokenClaimsParameters>({
        aud: ["https://audience.example.com", "https://audience.example.net"],
      });
    });

    it("should return a JSON Web Token Claims with an Expires At.", () => {
      let claims!: JsonWebTokenClaims;
      const exp = Date.now();

      expect(() => (claims = new JsonWebTokenClaims({ exp }))).not.toThrow();
      expect(claims.parameters).toStrictEqual<JsonWebTokenClaimsParameters>({ exp });
    });

    it("should return a JSON Web Token Claims with a Not Before.", () => {
      let claims!: JsonWebTokenClaims;
      const nbf = 1;

      expect(() => (claims = new JsonWebTokenClaims({ nbf }))).not.toThrow();
      expect(claims.parameters).toStrictEqual<JsonWebTokenClaimsParameters>({ nbf });
    });

    it("should return a JSON Web Token Claims with an Issued At.", () => {
      let claims!: JsonWebTokenClaims;
      const iat = Math.floor(Date.now() / 1000);

      expect(() => (claims = new JsonWebTokenClaims({ iat }))).not.toThrow();
      expect(claims.parameters).toStrictEqual<JsonWebTokenClaimsParameters>({ iat });
    });

    it("should return a JSON Web Token Claims with a JSON Web Token Identifier.", () => {
      let claims!: JsonWebTokenClaims;

      expect(() => (claims = new JsonWebTokenClaims({ jti: "758101ac-ce82-49e4-9d43-1e5bfc622593" }))).not.toThrow();

      expect(claims.parameters).toStrictEqual<JsonWebTokenClaimsParameters>({
        jti: "758101ac-ce82-49e4-9d43-1e5bfc622593",
      });
    });

    it('should not throw when the JSON Web Token Claims is expired but the validation option "ignoreExpired" is true.', () => {
      let claims!: JsonWebTokenClaims;
      const exp = Math.floor(Date.now() / 1000 - 86_400);

      expect(() => (claims = new JsonWebTokenClaims({ exp }, { ignoreExpired: true }))).not.toThrow();
      expect(claims.parameters).toStrictEqual<JsonWebTokenClaimsParameters>({ exp });
    });

    it("should return a JSON Web Token Claims that passes the provided validations.", () => {
      let claims!: JsonWebTokenClaims;
      const now = Math.floor(Date.now() / 1000);

      expect(() => {
        claims = new JsonWebTokenClaims(
          { exp: now + 86_400, iat: now, iss: "https://issuer.example.com" },
          {
            validationOptions: {
              aud: { essential: false, value: "https://audience.example.com" },
              exp: { value: now + 86_400 },
              iat: { values: [now] },
              iss: null,
              jti: {
                essential: false,
                values: ["758101ac-ce82-49e4-9d43-1e5bfc622593", "57936fbd-0868-4ecb-9466-a83e9b5a318b"],
              },
              sub: { essential: false },
            },
          },
        );
      }).not.toThrow();

      expect(claims.parameters).toStrictEqual<JsonWebTokenClaimsParameters>({
        exp: now + 86_400,
        iat: now,
        iss: "https://issuer.example.com",
      });
    });
  });

  describe("toString()", () => {
    it("should return the string representation of the JSON Web Token Claims.", () => {
      const claims = new JsonWebTokenClaims({ iat: 1_723_010_455, sub: "078BWDDXasdcg8" });
      expect(claims.toString()).toBe('{"iat":1723010455,"sub":"078BWDDXasdcg8"}');
    });
  });

  describe("toBuffer()", () => {
    it("should return the string representation of the JSON Web Token Claims.", () => {
      const claims = new JsonWebTokenClaims({ iat: 1_723_010_455, sub: "078BWDDXasdcg8" });
      expect(claims.toBuffer()).toStrictEqual(Buffer.from('{"iat":1723010455,"sub":"078BWDDXasdcg8"}', "utf8"));
    });
  });
});
