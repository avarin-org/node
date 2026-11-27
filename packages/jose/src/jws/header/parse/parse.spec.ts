import { JSON } from "@avarin/primitives/json";
import { afterEach, describe, expect, it, vi } from "vitest";

import { jose } from "../../../jose/index.ts";
import type { JsonWebSignatureHeaderParameters } from "../jsonwebsignature.header.parameters.ts";
import { JsonWebSignatureHeader } from "../jsonwebsignature.header.ts";
import { parse } from "./parse.ts";

describe("parse()", () => {
  const parameters: JsonWebSignatureHeaderParameters = { alg: "HS256" };
  const additionalParameters: Partial<JsonWebSignatureHeaderParameters> = { kid: "a3SnEtKLEJszzHsF" };

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("should call jose.header.parse() with the JSON Web Signature Header as its constructor.", async () => {
    const joseHeaderParseSpy = vi.spyOn(jose.header, "parse");

    await expect(parse(JSON.stringify(parameters), additionalParameters)).resolves.toBeInstanceOf(
      JsonWebSignatureHeader,
    );

    expect(joseHeaderParseSpy).toHaveBeenCalledExactlyOnceWith(
      JsonWebSignatureHeader,
      JSON.stringify(parameters),
      additionalParameters,
    );
  });
});
