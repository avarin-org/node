import { afterEach, describe, expect, it, vi } from "vitest";

import { jose } from "../../../jose/index.ts";
import type { JsonWebSignatureHeaderParameters } from "../jsonwebsignature.header.parameters.ts";
import { JsonWebSignatureHeader } from "../jsonwebsignature.header.ts";
import { create } from "./create.ts";

describe("create()", () => {
  const parameters: JsonWebSignatureHeaderParameters = { alg: "RS256" };
  const additionalParameters: Partial<JsonWebSignatureHeaderParameters> = { kid: "cfiJLCfs7qLnnLEA" };

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("should call jose.header.create() with the JSON Web Signature Header as its constructor.", async () => {
    const joseHeaderCreateSpy = vi.spyOn(jose.header, "create");

    await expect(create(parameters, additionalParameters)).resolves.toBeInstanceOf(JsonWebSignatureHeader);

    expect(joseHeaderCreateSpy).toHaveBeenCalledExactlyOnceWith(
      JsonWebSignatureHeader,
      parameters,
      additionalParameters,
    );
  });
});
