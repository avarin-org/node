import { JSON } from "@avarin/primitives/json";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { InvalidJsonWebKeySetError } from "../../errors/invalid-jsonwebkeyset.error.ts";
import type { JsonWebKeySetParameters } from "../../jwks/jsonwebkeyset.parameters.ts";
import { JsonWebKeySet } from "../../jwks/jsonwebkeyset.ts";
import { getJsonWebKeySetFromUrl } from "./get-jsonwebkeyset-from-url.ts";

const fetchMock = vi.fn<typeof globalThis.fetch>();

describe("getJsonWebKeySetFromUrl()", () => {
  const parameters: JsonWebKeySetParameters = {
    keys: [
      {
        crv: "P-256",
        kid: "ec-kid",
        kty: "EC",
        x: "4c_cS6IT6jaVQeobt_6BDCTmzBaBOTmmiSCpjd5a6Og",
        y: "mnrPnCFTDkGdEwilabaqM7DzwlAFgetZTmP9ycHPxF8",
      },
      {
        e: "AQAB",
        kid: "rsa-kid",
        kty: "RSA",
        n:
          "xjpFydzTbByzL5jhEa2yQO63dpS9d9SKaN107AR69skKiTR4uK1c4SzDt4YcurDB" +
          "yhgKNzeBo6Vq3IRrkrltp97LKWfeZdM-leGt8-UTZEWqrNf3UGOEj8kI6lbjiG-S" +
          "n_yNHcVA9qBV22norZkgXctHLeFbY6TmpD-I8_UiplZUHoc9KlYc7crCQRa-O7tK" +
          "FDULNTMjjifc0dmuYP7ZcYAZXmRmoOpQuDr8s7OZY7TAqN0btMfA7RpUCWLT6TMR" +
          "QPX8GcyTxfbkOrSTFueKMHVNdXDtl068XXJ9mkjORiEmwlzqSBoxdeLWcNf_u20S" +
          "5JG5iK0nsm1uZYu-02XN-w",
      },
    ],
  };

  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.resetAllMocks();
  });

  it("should throw when getting an error while calling the json web key set url.", async () => {
    fetchMock.mockResolvedValueOnce({ ok: false } as Response);

    const error = new InvalidJsonWebKeySetError("Failed to parse a JSON Web Key Set from the provided URL.");
    await expect(getJsonWebKeySetFromUrl("https://jsonwebkeyset.example.com")).rejects.toThrow(error);
  });

  it("should throw when the json web key set url returns an invalid json web key set.", async () => {
    fetchMock.mockResolvedValueOnce({ ok: true, status: 200, text: async () => "aabbccddeeff" } as Response);

    const error = new InvalidJsonWebKeySetError("The provided JSON Web Key Set Parameters is invalid.");
    await expect(getJsonWebKeySetFromUrl("https://jsonwebkeyset.example.com")).rejects.toThrow(error);
  });

  it("should return the json web key set.", async () => {
    let jsonWebKeySet!: JsonWebKeySet;

    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      text: async () => JSON.stringify(parameters),
    } as Response);

    await expect(
      (async () => {
        jsonWebKeySet = await getJsonWebKeySetFromUrl("http://jsonwebkeyset.example.com");
      })(),
    ).resolves.not.toThrow();

    expect(jsonWebKeySet).toBeInstanceOf(JsonWebKeySet);
    expect(jsonWebKeySet.keys.map((key) => key.parameters)).toStrictEqual(parameters.keys);
  });
});
