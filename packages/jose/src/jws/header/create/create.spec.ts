import { Buffer } from "node:buffer";
import { X509Certificate } from "node:crypto";

import { JSON } from "@avarin/primitives/json";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { InvalidJoseHeaderError } from "../../../errors/invalid-jose-header.error.ts";
import { InvalidJsonWebKeyError } from "../../../errors/invalid-jsonwebkey.error.ts";
import { JsonWebKey } from "../../../jwk/jsonwebkey.ts";
import type { JsonWebSignatureHeaderParameters } from "../jsonwebsignature.header.parameters.ts";
import type { JsonWebSignatureHeader } from "../jsonwebsignature.header.ts";
import { create } from "./create.ts";

const fetchMock = vi.fn<typeof globalThis.fetch>();

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
  const parameters: JsonWebSignatureHeaderParameters = { alg: "RS256" };

  const parametersWithJwkAndX509Chain: JsonWebSignatureHeaderParameters = {
    alg: "RS256",
    jwk: {
      e: "AQAB",
      kid: "rsa-key",
      kty: "RSA",
      n:
        "oZ9ANo0w0XDqLw29D7ZM_Qd8fR-6B_3l-MZ0CLikkfz71ivN28vm8hR4FIQJZAzR" +
        "MdJXNDPVW3RG7ygCMVRgPl7IDAaU-ZIsowPoV63WePYZGd_x5MVdn9ZXzzSohw8u" +
        "oJHYFwIn_RAHWNjS8e9_PpT2I3LhBbzm4k5rGJS8j2N1OC0DyGVLAc5Bif2klH7x" +
        "-WPzFxqpCBLVfy9vQ1rtCo2Nwt9zlC1SLoiky7JxPwk3-4RuqRvUBhAZ_xyjbo68" +
        "k9rfkPW1JqV-27ZbXHOH4rf6zAlEFjWOnKJsWYIKJDBHN2et6EpVgH66rZb-_fqf" +
        "Kqx1xeZT-YlfVK0MtakHKw",
    },
    x5c: [
      "MIIDBjCCAe6gAwIBAgIUfGXBlyYZdDvo6NWkapYYyZJCkNwwDQYJKoZIhvcNAQEL" +
        "BQAwIzEhMB8GA1UEAwwYUmV2ZW5za3kgSW50ZXJtZWRpYXRlIENBMB4XDTI2MDIy" +
        "NzE5NDkwN1oXDTI3MDIyNzE5NDkwN1owEzERMA8GA1UEAwwIUmV2ZW5za3kwggEi" +
        "MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQChn0A2jTDRcOovDb0Ptkz9B3x9" +
        "H7oH/eX4xnQIuKSR/PvWK83by+byFHgUhAlkDNEx0lc0M9VbdEbvKAIxVGA+XsgM" +
        "BpT5kiyjA+hXrdZ49hkZ3/HkxV2f1lfPNKiHDy6gkdgXAif9EAdY2NLx738+lPYj" +
        "cuEFvObiTmsYlLyPY3U4LQPIZUsBzkGJ/aSUfvH5Y/MXGqkIEtV/L29DWu0KjY3C" +
        "33OULVIuiKTLsnE/CTf7hG6pG9QGEBn/HKNujryT2t+Q9bUmpX7btltcc4fit/rM" +
        "CUQWNY6comxZggokMEc3Z63oSlWAfrqtlv79+p8qrHXF5lP5iV9UrQy1qQcrAgMB" +
        "AAGjQjBAMB0GA1UdDgQWBBRkNTEtKpoT13zSSmmklu5TToxx2DAfBgNVHSMEGDAW" +
        "gBTSjEMShDHN1LVx8GjgR/DOAgMxFDANBgkqhkiG9w0BAQsFAAOCAQEARrcDkPHu" +
        "DVBNpvWLsh3052vt9Wg9twmPUFFoDgdob9j0hpSoqeYzf/ztHjnCcAUr48gKFJMI" +
        "7BxRbi9No8JaAOtbq1aGr53Ozd0hSATef3aP4p5NsIWrXxC26VTMW+kjo3YKwVdR" +
        "pyz2DKSN7RBUhmO0X0YCvo7P88yDtOBQyKlsqI7mLyv7WX1mJ2Y/zvvK14RLt17Z" +
        "A9YojROLhyZUVv+4hFALwZugNSZqKCE8VS7XA13zVE/hC7IyzjIPoutjbEuj5Abb" +
        "WINOOIchBLxly2TCzE/kkrZ8uPOEghR71os9L+u6oYu+q4jh9LY2D9nHSg5y1jkq" +
        "3NJ5yD2vzvXZ2Q==",
      "MIIDCTCCAfGgAwIBAgIULim7Ch5k1Ut89QZvejuclYahzcMwDQYJKoZIhvcNAQEL" +
        "BQAwFjEUMBIGA1UEAwwLUmV2ZW5za3kgQ0EwHhcNMjYwMjI3MTk0ODM1WhcNMjcw" +
        "MjI3MTk0ODM1WjAjMSEwHwYDVQQDDBhSZXZlbnNreSBJbnRlcm1lZGlhdGUgQ0Ew" +
        "ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDKdCihPzetkTXTROiqNonp" +
        "/uFhuk0Nm1DgZo230aVWN8paNuuXxKkzXyESROJtb+AaTvYPamfs9L97EF93hFZ+" +
        "A7+8lDRx9FGNhU9y1ambaTo8COXr0FtktmtPNtWG6BeHojuMHzkY6YWaGqi/FhM4" +
        "xr6TKsXqC4TTzdtShl96qXrJySmCtAIjlMRRqn4skz6oJ8JVMDeOCg0/73zy942O" +
        "210+/91+ONnmPwbDZvz+UkEj/yMD0dE90dYWUEhltoU8A5gVOzVHVxd0/HCvVBIB" +
        "kfdU9YtxykoTBG+5puQOBZTORLG/mKKeHj4LX4mrid7zehL8NkXMPX9f5kbQ3WWB" +
        "AgMBAAGjQjBAMB0GA1UdDgQWBBTSjEMShDHN1LVx8GjgR/DOAgMxFDAfBgNVHSME" +
        "GDAWgBSi8AliI6vKZPBIsVfHYPCba32i0zANBgkqhkiG9w0BAQsFAAOCAQEAZaH/" +
        "ZIPa7GA3RqrF10cDFePFkZIPfLKzcHXko4DhaaJZlGxnOwJ+bZN4q7TOBe/qyknv" +
        "oMPfZrjxK05wM7CjYBWdK8n4rIsPmcxzVEMCbHNSET+Pf1y3yehdIk1e/cY82puz" +
        "eBYIbu2Axl2qvKJTeFASl0Wq51nJ1GTLMvaOFiP5q1YXKZhDRjMW/8d/HDerDNYw" +
        "lPwxFUpDiUSiMxR7HG46rTTv+hiJEPh+etQi15oxDYLoTaXP90Z5m43DnndgSR5e" +
        "UEhmK4x1z1RSeTKmJg3mmMcXkuO0Xa2UE8++NANzcysfOoTMKl+3V7N4QSFuGEW3" +
        "y13j5RKviQ3smEdBvA==",
      "MIIDDTCCAfWgAwIBAgIUGAy8oskSYRmqzuIb1/PNUBU0KEEwDQYJKoZIhvcNAQEL" +
        "BQAwFjEUMBIGA1UEAwwLUmV2ZW5za3kgQ0EwHhcNMjYwMjI3MTk0NzMxWhcNMjcw" +
        "MjI3MTk0NzMxWjAWMRQwEgYDVQQDDAtSZXZlbnNreSBDQTCCASIwDQYJKoZIhvcN" +
        "AQEBBQADggEPADCCAQoCggEBAKsCpcaP9+s0EeNWdZUBO5o2ujDTjVWjGHtf0z2O" +
        "/4nfXPnQdmKNQbF0zQLPbkAKyinN5uwJjcQE33eybR4VPyFVpKDE6ytAmgFNG9+R" +
        "9fmcvhaTsN6uzenl8Us5uR+BpIHsLSa/6EYT2vTgBSbbG7W644IZnTR2dQ70iSJv" +
        "gMw+hGQuBLCjZk6ElN1Y3z4ygeTyVSgoKPeCCUO+uGKhk7rJ01LrhvUFSqO6prjE" +
        "UnM9qnfAvI3BgHX6aItVdYDIZxx+ybinyl/JcV8URDjxbytj1G5UEHNCuRc+pjzt" +
        "gBRsZNed+11Z0sGO4zJMwcHDNwNRRAw+VABmoIIHgcxtR7cCAwEAAaNTMFEwHQYD" +
        "VR0OBBYEFKLwCWIjq8pk8EixV8dg8JtrfaLTMB8GA1UdIwQYMBaAFKLwCWIjq8pk" +
        "8EixV8dg8JtrfaLTMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB" +
        "AEb2ad6R150bFvh++1csVg2pJBJhVvkDVLw1VSW10L4WW339wgrtmlWeBMlcFFJ9" +
        "j++9HTtce5OB0dIytG8D/E0w6SUcMFpYL6pa4mIx54oZGe2l7iwSGS/NSfnGrcP1" +
        "Z8IsW5C+jThFR3RStHul4/soA9rgroNcvCNaiibiUpBlz5S8f0d8KkEHlwmNsAZv" +
        "4JmECqRPQRk2N6ZqtOhwFAZskyLOF9kreD4CdFKxucCc9jv2UIUtlR9X9IsGsrV2" +
        "R95IzriYmlniFv98U6m+Q8JGGnBcj0caVsxUqIp2oqGi3oUMoYWBekY52ELzKxLd" +
        "/p0IrAZpxzqzw3OqXnCSvZk=",
    ],
  };

  const pemCertificateChain = parametersWithJwkAndX509Chain
    .x5c!.map((certificate) => `-----BEGIN CERTIFICATE-----\n${certificate}\n-----END CERTIFICATE-----\n`)
    .join("");

  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.resetAllMocks();
  });

  it.each(invalidParameters)(
    "should throw when the provided JSON Web Signature Header Parameters is invalid.",
    async (_parameters) => {
      const error = new InvalidJoseHeaderError("The provided JSON Web Signature Header Parameters is invalid.");
      await expect(create(_parameters)).rejects.toThrow(error);
    },
  );

  it.each(invalidAdditionalParameters)(
    "should throw when the provided additional JSON Web Signature Header Parameters is invalid.",
    async (additionalParameters) => {
      const error = new InvalidJoseHeaderError("The provided JSON Web Signature Header Parameters is invalid.");
      await expect(create(parameters, additionalParameters)).rejects.toThrow(error);
    },
  );

  it("should throw when the provided JSON Web Signature Header Parameters are invalid.", async () => {
    await expect(create({ alg: "A128KW" } as any)).rejects.toThrow(InvalidJoseHeaderError);
  });

  it("should throw when failing to get a JSON Web Key from the provided JSON Web Signature Header Parameters.", async () => {
    await expect(create({ ...parameters, jwk: { e: "AQAB", kty: "oct" } })).rejects.toThrow(InvalidJoseHeaderError);
  });

  it("should throw when failing to get a X.509 Certificate Chain from the provided JSON Web Signature Header Parameters.", async () => {
    await expect(create({ ...parameters, x5c: ["abcdef0123456789"] })).rejects.toThrow(InvalidJsonWebKeyError);
  });

  it("should throw when the X.509 Certificate fails to verify the JSON Web Key.", async () => {
    await expect(
      create({
        ...parametersWithJwkAndX509Chain,
        x5c: [parametersWithJwkAndX509Chain.x5c![1]!],
      }),
    ).rejects.toThrow(InvalidJsonWebKeyError);
  });

  it("should return a JSON Web Signature Header without a JSON Web Key and an X.509 Certificate Chain.", async () => {
    let header!: JsonWebSignatureHeader;

    await expect(
      (async () => {
        header = await create(parameters, { kid: "rsa-key" });
      })(),
    ).resolves.not.toThrow();

    expect(header.certificateChain).toBeNull();
    expect(header.jsonWebKey).toBeNull();
    expect(header.parameters).toStrictEqual<JsonWebSignatureHeaderParameters>({ ...parameters, kid: "rsa-key" });
  });

  it('should return a JSON Web Signature Header with a JSON Web Key from the provided JSON Web Signature Header Parameter "jku".', async () => {
    let header!: JsonWebSignatureHeader;

    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ keys: [parametersWithJwkAndX509Chain.jwk!] }),
    } as Response);

    const params: JsonWebSignatureHeaderParameters = {
      ...parameters,
      jku: "https://jsonwebkeyset.example.com",
      kid: "rsa-key",
    };

    await expect(
      (async () => {
        header = await create(params);
      })(),
    ).resolves.not.toThrow();

    expect(header.certificateChain).toBeNull();

    expect(header.jsonWebKey).toBeInstanceOf(JsonWebKey);
    expect(header.jsonWebKey!.parameters).toStrictEqual(parametersWithJwkAndX509Chain.jwk);

    expect(header.parameters).toStrictEqual(params);
  });

  it('should return a JSON Web Signature Header with a JSON Web Key from the provided JSON Web Signature Header Parameter "jwk".', async () => {
    let header!: JsonWebSignatureHeader;

    const { x5c: _, ...params } = parametersWithJwkAndX509Chain;

    await expect(
      (async () => {
        header = await create(params);
      })(),
    ).resolves.not.toThrow();

    expect(header.certificateChain).toBeNull();

    expect(header.jsonWebKey).toBeInstanceOf(JsonWebKey);
    expect(header.jsonWebKey!.parameters).toStrictEqual(parametersWithJwkAndX509Chain.jwk);

    expect(header.parameters).toStrictEqual(params);
  });

  it('should return a JSON Web Signature Header with an X.509 Certificate Chain from the provided JSON Web Signature Header Parameter "x5u".', async () => {
    let header!: JsonWebSignatureHeader;

    fetchMock.mockResolvedValueOnce({ ok: true, status: 200, text: async () => pemCertificateChain } as Response);

    const params: JsonWebSignatureHeaderParameters = { ...parameters, x5u: "https://certificate.example.com" };

    await expect(
      (async () => {
        header = await create(params);
      })(),
    ).resolves.not.toThrow();

    expect(header.certificateChain).toHaveLength(3);
    expect(header.certificateChain).toSatisfy((value: unknown[]) =>
      value.every((certificate) => certificate instanceof X509Certificate),
    );

    expect(header.jsonWebKey).toBeNull();

    expect(header.parameters).toStrictEqual(params);
  });

  it('should return a JSON Web Signature Header with an X.509 Certificate Chain from the provided JSON Web Signature Header Parameter "x5c".', async () => {
    let header!: JsonWebSignatureHeader;

    const { jwk: _, ...params } = parametersWithJwkAndX509Chain;

    await expect(
      (async () => {
        header = await create(params);
      })(),
    ).resolves.not.toThrow();

    expect(header.certificateChain).toHaveLength(3);
    expect(header.certificateChain).toSatisfy((value: unknown[]) =>
      value.every((certificate) => certificate instanceof X509Certificate),
    );

    expect(header.jsonWebKey).toBeNull();

    expect(header.parameters).toStrictEqual(params);
  });

  it("should return a JSON Web Signature Header with a JSON Web Key and an X.509 Certificate Chain.", async () => {
    let header!: JsonWebSignatureHeader;

    await expect(
      (async () => {
        header = await create(parametersWithJwkAndX509Chain);
      })(),
    ).resolves.not.toThrow();

    expect(header.certificateChain).toHaveLength(3);
    expect(header.certificateChain).toSatisfy((value: unknown[]) =>
      value.every((certificate) => certificate instanceof X509Certificate),
    );

    expect(header.jsonWebKey).toBeInstanceOf(JsonWebKey);
    expect(header.jsonWebKey!.parameters).toStrictEqual(parametersWithJwkAndX509Chain.jwk);

    expect(header.parameters).toStrictEqual(parametersWithJwkAndX509Chain);
  });
});
