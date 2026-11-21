import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import type { KeyType } from "../../jwa/jwk/key-type.type.ts";
import type { JsonWebKeyParameters } from "../jsonwebkey.parameters.ts";
import type { JsonWebKey } from "../jsonwebkey.ts";
import { generate } from "./generate.ts";

const invalidKeyTypes: any[] = [
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
  "a",
];

const keyTypeAndOptions: [KeyType, NodeJS.Dict<unknown>][] = [
  ["EC", { curve: "P-256" }],
  ["RSA", { modulus: 2048 }],
  ["oct", { length: 256 }],
];

describe("generate()", () => {
  it.each(invalidKeyTypes)("should throw when the provided JSON Web Key Key Type is invalid.", async (kty) => {
    const error = new TypeError("The provided JSON Web Key Key Type is invalid.");
    await expect(generate(kty, {})).rejects.toThrow(error);
  });

  it.each(keyTypeAndOptions)("should return the generated JSON Web Key.", async (kty, options) => {
    let jsonWebKey!: JsonWebKey;

    await expect(
      (async () => {
        jsonWebKey = await generate(kty, options, { kid: "CZ0tnUHwtha3ehpP" });
      })(),
    ).resolves.not.toThrow();

    expect(jsonWebKey.parameters).toMatchObject<Partial<JsonWebKeyParameters>>({ kid: "CZ0tnUHwtha3ehpP", kty });
    expect(jsonWebKey.certificateChain).toBeNull();
  });
});
