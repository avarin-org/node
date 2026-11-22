import { beforeAll, describe, expect, it } from "vitest";

import { InvalidJsonWebKeyError } from "../errors/invalid-jsonwebkey.error.ts";
import type { EllipticCurveJsonWebKeyParameters } from "../jwa/jwk/ec/elliptic-curve.jsonwebkey.parameters.ts";
import type { RsaJsonWebKeyParameters } from "../jwa/jwk/rsa/rsa.jsonwebkey.parameters.ts";
import { jwk } from "../jwk/index.ts";
import type { JsonWebKeySetParameters } from "./jsonwebkeyset.parameters.ts";
import { JsonWebKeySet } from "./jsonwebkeyset.ts";

describe("JSON Web Key Set", () => {
  const publicEllipticCurveParameters: EllipticCurveJsonWebKeyParameters = {
    crv: "P-256",
    kty: "EC",
    x: "4c_cS6IT6jaVQeobt_6BDCTmzBaBOTmmiSCpjd5a6Og",
    y: "mnrPnCFTDkGdEwilabaqM7DzwlAFgetZTmP9ycHPxF8",
  };

  const privateEllipticCurveParameters: EllipticCurveJsonWebKeyParameters = {
    ...publicEllipticCurveParameters,
    d: "bwVX6Vx-TOfGKYOPAcu2xhaj3JUzs-McsC-suaHnFBo",
  };

  const publicRsaParameters: RsaJsonWebKeyParameters = {
    e: "AQAB",
    kty: "RSA",
    n:
      "xjpFydzTbByzL5jhEa2yQO63dpS9d9SKaN107AR69skKiTR4uK1c4SzDt4YcurDB" +
      "yhgKNzeBo6Vq3IRrkrltp97LKWfeZdM-leGt8-UTZEWqrNf3UGOEj8kI6lbjiG-S" +
      "n_yNHcVA9qBV22norZkgXctHLeFbY6TmpD-I8_UiplZUHoc9KlYc7crCQRa-O7tK" +
      "FDULNTMjjifc0dmuYP7ZcYAZXmRmoOpQuDr8s7OZY7TAqN0btMfA7RpUCWLT6TMR" +
      "QPX8GcyTxfbkOrSTFueKMHVNdXDtl068XXJ9mkjORiEmwlzqSBoxdeLWcNf_u20S" +
      "5JG5iK0nsm1uZYu-02XN-w",
  };

  const privateRsaParameters: RsaJsonWebKeyParameters = {
    ...publicRsaParameters,
    d:
      "cc2YrWia9LGRad0SMe0PrlmeeHSyRe5-u--QJcP4uF_5LYYzXIsjDJ9_iYh0S_YY" +
      "e6bLjqHOSp44OHvJqoXMX5j3-ECKnNjnUHMtRB2awXGBqBOhB8TqoQXgmXDi1jx_" +
      "6Fu8xH-vaSfpwrsN-0QzIcYHil6b8hwE0f0r6istBmL7iayJbnONp7na9ow2fUQl" +
      "nr41vsHZa4knTZ2E2kq5ntgaXlF6AIdc4DD_BZpf2alEbhQMX9T168ZsSyAs7wKS" +
      "d3ivhHRQayXEapUfZ_ykvnF4-DoVI1iRoowgZ-dlnv4Ff3YrKQ3Zv3uHJcF1BtWQ" +
      "VipOIHx4GyIc4bmTSA5PEQ",
    dp:
      "vqtDX-2DjgtZY_3Y-eiJMRBjmVgfiZ4r1RWjrCddWEVrauafPVKULy6F09s6tqnq" +
      "rqvBgjZk0ROtgCCHZB0NNRNqkdlJWUP1vWdDsf8FyjBfU_J2OlmSOOydV_zjVbX_" +
      "-vumYUsN2M5b3Vk1nmiLgplryhLq_JDzghnnqG6CN-0",
    dq:
      "tKczxBhSwbcpu5i70fLH1iJ5BNAkSyTbdSCNYQYAqKee2Elo76lbhixmuP6upIdb" +
      "SHO9mZd8qov0MXTV1lEOrNc2KbH5HTkb1wRZ1dwlReDFdKUxxjYBtb9zpM93_XVx" +
      "btSgPPbnBBL-S_OCPVtyzS_f-49hGoF52KHGns3v0hE",
    p:
      "-ZFuDg38cG-e5L6h1Jbn8ngifWgHx8m1gybkY7yEpU1V02fvQAMI1XG-1WpZm2xj" +
      "j218wNCj0BCEdmdBqZMk5RlzLagtfzQ3rPO-ucYPZ_SDmy8Udzr-sZLCqMFyLtxk" +
      "gMfGo4QZ6UJWYpTCCmZ92nS_pa4ePrQdlpnS4DLv_SM",
    q:
      "y1YdZtsbYfCOdsYBZrDpcvubwMN2fKRAzETYW5sqYv8XkxHG1J1zHH-zWJBQfZhT" +
      "biHPgHvoaFykEm9xhuA77RFGRXxFUrGBtfqIx_OG-kRWudmH83EyMzMoKQaW98RX" +
      "WqRO1JDlcs4_vzf_KN63zQKv5i4UdiiObQkZCYIOVUk",
    qi:
      "C4q9uIi-1fYhE0NTWVNzdhSi7fA3uznTWaW1X5LWBF4gBOcWvMMTfOZEaPjtY2WP" +
      "XaTWU4bdVN0GgktVLUDPLrSj533W1cOQZb_mm_7BFNrleelruT87bZhWPYQ979kl" +
      "6590ySgbH81pEM8FQW1JBATz0MYtUNZAt8N360vayE4",
  };

  describe("find()", () => {
    let jsonWebKeySet: JsonWebKeySet;

    beforeAll(async () => {
      jsonWebKeySet = new JsonWebKeySet([
        await jwk.create(publicEllipticCurveParameters, { kid: "ec-key", use: "sig" }),
        await jwk.create(publicRsaParameters, { key_ops: ["encrypt"], kid: "rsa-key" }),
      ]);
    });

    it("should return null when no JSON Web Key matches the provided predicate.", () => {
      expect(jsonWebKeySet.find((key) => key.kid === "unknown")).toBeNull();
    });

    it("should return the JSON Web Key that matches the provided predicate.", () => {
      expect(jsonWebKeySet.find((key) => key.kid === "ec-key")).toStrictEqual(jsonWebKeySet.keys[0]!);

      // oxlint-disable-next-line vitest/no-conditional-in-test
      expect(jsonWebKeySet.find((key) => key.key_ops?.includes("encrypt") ?? false)).toStrictEqual(
        jsonWebKeySet.keys[1]!,
      );
    });
  });

  describe("get()", () => {
    let jsonWebKeySet: JsonWebKeySet;

    beforeAll(async () => {
      jsonWebKeySet = new JsonWebKeySet([
        await jwk.create(publicEllipticCurveParameters, { kid: "ec-key", use: "sig" }),
        await jwk.create(publicRsaParameters, { key_ops: ["encrypt"], kid: "rsa-key" }),
      ]);
    });

    it("should throw when no JSON Web Key matches the provided predicate.", () => {
      const error = new InvalidJsonWebKeyError("No JSON Web Key matches the criteria in the JSON Web Key Set.");
      expect(() => jsonWebKeySet.get((key) => key.kid === "unknown")).toThrow(error);
    });

    it("should return the JSON Web Key that matches the provided predicate.", () => {
      expect(jsonWebKeySet.get((key) => key.kid === "ec-key")).toStrictEqual(jsonWebKeySet.keys[0]!);

      // oxlint-disable-next-line vitest/no-conditional-in-test
      expect(jsonWebKeySet.get((key) => key.key_ops?.includes("encrypt") ?? false)).toStrictEqual(
        jsonWebKeySet.keys[1]!,
      );
    });
  });

  describe("toJSON()", () => {
    it("should return the Public JSON Web Key Set Parameters when exportPrivate is not set.", async () => {
      const jsonWebKeySet = new JsonWebKeySet([
        await jwk.create(publicEllipticCurveParameters, { kid: "ec-pub-key", use: "sig" }),
        await jwk.create(privateEllipticCurveParameters, { kid: "ec-priv-key", use: "sig" }),
        await jwk.create(publicRsaParameters, { key_ops: ["encrypt"], kid: "rsa-pub-key" }),
        await jwk.create(privateRsaParameters, { key_ops: ["decrypt"], kid: "rsa-priv-key" }),
      ]);

      expect(jsonWebKeySet.toJSON()).toStrictEqual<JsonWebKeySetParameters>({
        keys: [
          { ...publicEllipticCurveParameters, kid: "ec-pub-key", use: "sig" },
          { ...publicEllipticCurveParameters, kid: "ec-priv-key", use: "sig" },
          { ...publicRsaParameters, key_ops: ["encrypt"], kid: "rsa-pub-key" },
          { ...publicRsaParameters, key_ops: ["decrypt"], kid: "rsa-priv-key" },
        ],
      });
    });

    it("should return the Public JSON Web Key Set Parameters when exportPrivate is false.", async () => {
      const jsonWebKeySet = new JsonWebKeySet([
        await jwk.create(publicEllipticCurveParameters, { kid: "ec-pub-key", use: "sig" }),
        await jwk.create(privateEllipticCurveParameters, { kid: "ec-priv-key", use: "sig" }),
        await jwk.create(publicRsaParameters, { key_ops: ["encrypt"], kid: "rsa-pub-key" }),
        await jwk.create(privateRsaParameters, { key_ops: ["decrypt"], kid: "rsa-priv-key" }),
      ]);

      expect(jsonWebKeySet.toJSON(false)).toStrictEqual<JsonWebKeySetParameters>({
        keys: [
          { ...publicEllipticCurveParameters, kid: "ec-pub-key", use: "sig" },
          { ...publicEllipticCurveParameters, kid: "ec-priv-key", use: "sig" },
          { ...publicRsaParameters, key_ops: ["encrypt"], kid: "rsa-pub-key" },
          { ...publicRsaParameters, key_ops: ["decrypt"], kid: "rsa-priv-key" },
        ],
      });
    });

    it("should return the Private JSON Web Key Set Parameters when exportPrivate is true.", async () => {
      const jsonWebKeySet = new JsonWebKeySet([
        await jwk.create(publicEllipticCurveParameters, { kid: "ec-pub-key", use: "sig" }),
        await jwk.create(privateEllipticCurveParameters, { kid: "ec-priv-key", use: "sig" }),
        await jwk.create(publicRsaParameters, { key_ops: ["encrypt"], kid: "rsa-pub-key" }),
        await jwk.create(privateRsaParameters, { key_ops: ["decrypt"], kid: "rsa-priv-key" }),
      ]);

      expect(jsonWebKeySet.toJSON(true)).toStrictEqual<JsonWebKeySetParameters>({
        keys: [
          { ...publicEllipticCurveParameters, kid: "ec-pub-key", use: "sig" },
          { ...privateEllipticCurveParameters, kid: "ec-priv-key", use: "sig" },
          { ...publicRsaParameters, key_ops: ["encrypt"], kid: "rsa-pub-key" },
          { ...privateRsaParameters, key_ops: ["decrypt"], kid: "rsa-priv-key" },
        ],
      });
    });
  });
});
