import { Buffer } from "node:buffer";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { InvalidJsonWebTokenClaimsError } from "../../../errors/invalid-jsonwebtoken-claims.error.ts";
import type { JsonWebTokenClaimsParameters } from "../jsonwebtoken.claims.parameters.ts";
import { JsonWebTokenClaims } from "../jsonwebtoken.claims.ts";
import { create } from "./create.ts";

class CustomJsonWebTokenClaims extends JsonWebTokenClaims {}

const invalidParametersWithConstructor: any[] = [
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

const invalidParameters: any[] = [undefined, null, true, 1, 1.2, 1n, "a", Symbol("a"), Buffer.alloc(1), () => 1, []];

const invalidAdditionalParameters: any[] = [
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

describe("create()", () => {
  let now: number;

  let parameters: JsonWebTokenClaimsParameters;
  let additionalParameters: JsonWebTokenClaimsParameters;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-12T00:00:00Z"));

    now = Math.floor(Date.now() / 1000);

    parameters = {
      aud: "https://audience.example.com",
      exp: now + 3600,
      iat: now,
      iss: "https://issuer.example.com",
      jti: "758101ac-ce82-49e4-9d43-1e5bfc622593",
      nbf: now,
      sub: "https://subject.example.com",
    };

    additionalParameters = { nonce: "f594ad3b-3989-49eb-b03f-8fd63f005c2e" };
  });

  afterEach(() => {
    vi.clearAllTimers();
    vi.useRealTimers();
  });

  it("should throw when the provided JSON Web Token Claims Constructor is invalid.", async () => {
    const error = new TypeError("The provided JSON Web Token Claims Constructor is invalid.");
    await expect(create(Buffer as any, parameters)).rejects.toThrow(error);
  });

  it.each(invalidParametersWithConstructor)(
    "should throw when the provided JSON Web Token Claims Parameters is invalid with a custom JSON Web Token Claims Constructor.",
    async (_parameters) => {
      const error = new InvalidJsonWebTokenClaimsError("The provided JSON Web Token Claims Parameters is invalid.");
      await expect(create(CustomJsonWebTokenClaims, _parameters)).rejects.toThrow(error);
    },
  );

  it.each(invalidAdditionalParameters)(
    "should throw when the provided Additional JSON Web Token Claims Parameters is invalid with a custom JSON Web Token Claims Constructor.",
    async (_additionalParameters) => {
      const error = new InvalidJsonWebTokenClaimsError("The provided JSON Web Token Claims Parameters is invalid.");
      await expect(create(CustomJsonWebTokenClaims, parameters, _additionalParameters)).rejects.toThrow(error);
    },
  );

  it("should return a custom JSON Web Token Claims.", async () => {
    let claims!: CustomJsonWebTokenClaims;

    await expect(
      (async () => {
        claims = await create(CustomJsonWebTokenClaims, parameters, additionalParameters);
      })(),
    ).resolves.not.toThrow();

    expect(claims).toBeInstanceOf(CustomJsonWebTokenClaims);
    expect(claims.parameters).toStrictEqual<JsonWebTokenClaimsParameters>({ ...parameters, ...additionalParameters });
  });

  it.each(invalidParameters)(
    "should throw when the provided JSON Web Token Claims Parameters is invalid.",
    async (_parameters) => {
      const error = new InvalidJsonWebTokenClaimsError("The provided JSON Web Token Claims Parameters is invalid.");
      await expect(create(_parameters)).rejects.toThrow(error);
    },
  );

  it("should throw when the provided JSON Web Token Claims Constructor is invalid and the only argument.", async () => {
    const error = new TypeError("The provided JSON Web Token Claims Constructor is invalid.");
    await expect(create(Buffer as any)).rejects.toThrow(error);
  });

  it.each(invalidAdditionalParameters)(
    "should throw when the provided Additional JSON Web Token Claims Parameters is invalid.",
    async (_additionalParameters) => {
      const error = new InvalidJsonWebTokenClaimsError("The provided JSON Web Token Claims Parameters is invalid.");
      await expect(create(parameters, _additionalParameters)).rejects.toThrow(error);
    },
  );

  it("should return a JSON Web Token Claims.", async () => {
    let claims!: JsonWebTokenClaims;

    await expect(
      (async () => {
        claims = await create(parameters, additionalParameters);
      })(),
    ).resolves.not.toThrow();

    expect(claims).not.toBeInstanceOf(CustomJsonWebTokenClaims);
    expect(claims).toBeInstanceOf(JsonWebTokenClaims);
    expect(claims.parameters).toStrictEqual<JsonWebTokenClaimsParameters>({ ...parameters, ...additionalParameters });
  });
});
