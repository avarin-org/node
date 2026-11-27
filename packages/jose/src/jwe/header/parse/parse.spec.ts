import { JSON } from "@avarin/primitives/json";
import { afterEach, describe, expect, it, vi } from "vitest";

import { jose } from "../../../jose/index.ts";
import type { JsonWebEncryptionHeaderParameters } from "../jsonwebencryption.header.parameters.ts";
import { JsonWebEncryptionHeader } from "../jsonwebencryption.header.ts";
import { parse } from "./parse.ts";

describe("parse()", () => {
  const parameters: JsonWebEncryptionHeaderParameters = { alg: "A128KW", enc: "A256GCM" };
  const additionalParameters: Partial<JsonWebEncryptionHeaderParameters> = { kid: "BGi9dKfLX9TPcguE" };

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("should call jose.header.parse() with the JSON Web Encryption Header as its constructor.", async () => {
    const joseHeaderParseSpy = vi.spyOn(jose.header, "parse");

    await expect(parse(JSON.stringify(parameters), additionalParameters)).resolves.toBeInstanceOf(
      JsonWebEncryptionHeader,
    );

    expect(joseHeaderParseSpy).toHaveBeenCalledExactlyOnceWith(
      JsonWebEncryptionHeader,
      JSON.stringify(parameters),
      additionalParameters,
    );
  });
});
