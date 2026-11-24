import { Buffer } from "node:buffer";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { InvalidJoseHeaderError } from "../errors/invalid-jose-header.error.ts";
import type { JsonWebKeyParameters } from "../jwk/jsonwebkey.parameters.ts";
import type { JoseHeaderParameters } from "./jose-header.parameters.ts";
import { JoseHeader } from "./jose-header.ts";

const invalidJkus: any[] = [
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

const invalidJwks: any[] = [undefined, null, true, 1, 1.2, 1n, "a", Symbol("a"), Buffer, Buffer.alloc(1), () => 1, []];

const invalidKids: any[] = [
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

const invalidX5Us: any[] = [
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

const invalidX5Cs: any[] = [
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
];

const invalidX5Ts: any[] = [
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

const invalidX5TS256s: any[] = [
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

const invalidTyps: any[] = [
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

const invalidCtys: any[] = [
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

const invalidCrits: any[] = [
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
];

describe("JOSE Header", () => {
  const parameters: JoseHeaderParameters = {
    alg: "RS256",
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

  const jsonWebKeyParameters: JsonWebKeyParameters = {
    alg: "RS256",
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
    x5c: parameters.x5c!,
  };

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-12T00:00:00Z"));
  });

  afterEach(() => {
    vi.clearAllTimers();
    vi.useRealTimers();
  });

  describe("constructor", () => {
    it.each(invalidJkus)('should throw when the provided JOSE Header Parameter "jku" is invalid.', (jku) => {
      const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "jku".');
      expect(() => Reflect.construct(JoseHeader, [{ ...parameters, jku }])).toThrow(error);
    });

    it.each(invalidJwks)('should throw when the provided JOSE Header Parameter "jwk" is invalid.', (jwk) => {
      const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "jwk".');
      expect(() => Reflect.construct(JoseHeader, [{ ...parameters, jwk }])).toThrow(error);
    });

    it('should throw when providing both "jku" and "jwk" JOSE Header Parameters.', () => {
      const error = new InvalidJoseHeaderError('Cannot have both "jku" and "jwk" JOSE Header Parameters.');

      expect(() =>
        Reflect.construct(JoseHeader, [{ ...parameters, jku: "http://jku-url.com", jwk: jsonWebKeyParameters }]),
      ).toThrow(error);
    });

    it.each(invalidKids)('should throw when the provided JOSE Header Parameter "kid" is invalid.', (kid) => {
      const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "kid".');
      expect(() => Reflect.construct(JoseHeader, [{ ...parameters, kid }])).toThrow(error);
    });

    it.each(invalidX5Us)('should throw when the provided JOSE Header Parameter "x5u" is invalid.', (x5u) => {
      const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "x5u".');
      expect(() => Reflect.construct(JoseHeader, [{ ...parameters, x5u }])).toThrow(error);
    });

    it.each(invalidX5Cs)('should throw when the provided JOSE Header Parameter "x5c" is invalid.', (x5c) => {
      const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "x5c".');
      expect(() => Reflect.construct(JoseHeader, [{ ...parameters, x5c }])).toThrow(error);
    });

    it.each(invalidX5Ts)('should throw when the provided JOSE Header Parameter "x5t" is invalid.', (x5t) => {
      const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "x5t".');
      expect(() => Reflect.construct(JoseHeader, [{ ...parameters, x5t }])).toThrow(error);
    });

    it.each(invalidX5TS256s)(
      'should throw when the provided JOSE Header Parameter "x5t#S256" is invalid.',
      (x5tS256) => {
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "x5t#S256".');
        expect(() => Reflect.construct(JoseHeader, [{ ...parameters, "x5t#S256": x5tS256 }])).toThrow(error);
      },
    );

    it('should throw when providing both "x5u" and "x5c" JOSE Header Parameters.', () => {
      const error = new InvalidJoseHeaderError('Cannot have both "x5u" and "x5c" JOSE Header Parameters.');
      expect(() => Reflect.construct(JoseHeader, [{ ...parameters, x5u: "http://cert-url.com" }])).toThrow(error);
    });

    it("should throw when providing an X.509 Certificate Thumbprint without an X.509 Certificate Chain.", () => {
      const { x5c: _, ...params } = parameters;

      const error = new InvalidJoseHeaderError(
        "Cannot have an X.509 Certificate Thumbprint without an X.509 Certificate Chain.",
      );

      expect(() => Reflect.construct(JoseHeader, [{ ...params, x5t: "thumbprint" }])).toThrow(error);
      expect(() => Reflect.construct(JoseHeader, [{ ...params, "x5t#S256": "thumbprint" }])).toThrow(error);
    });

    it.each(invalidTyps)('should throw when the provided JOSE Header Parameter "typ" is invalid.', (typ) => {
      const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "typ".');
      expect(() => Reflect.construct(JoseHeader, [{ ...parameters, typ }])).toThrow(error);
    });

    it.each(invalidCtys)('should throw when the provided JOSE Header Parameter "cty" is invalid.', (cty) => {
      const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "cty".');
      expect(() => Reflect.construct(JoseHeader, [{ ...parameters, cty }])).toThrow(error);
    });

    it.each(invalidCrits)('should throw when the provided JOSE Header Parameter "crit" is invalid.', (crit) => {
      const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "crit".');
      expect(() => Reflect.construct(JoseHeader, [{ ...parameters, crit }])).toThrow(error);
    });

    it('should throw when the JOSE Header Parameter declared at "crit" is not provided.', () => {
      const error = new InvalidJoseHeaderError('Missing required JOSE Header Parameter "b64".');
      expect(() => Reflect.construct(JoseHeader, [{ ...parameters, crit: ["b64"] }])).toThrow(error);
    });

    it("should return a simple JOSE Header.", () => {
      let header!: JoseHeader;

      expect(() => (header = Reflect.construct(JoseHeader, [{ alg: "RS256" }]))).not.toThrow();

      expect(header.certificateChain).toBeNull();
      expect(header.jsonWebKey).toBeNull();
      expect(header.parameters).toStrictEqual<JoseHeaderParameters>({ alg: "RS256" });
    });

    it("should return a JOSE Header with extensions.", () => {
      let header!: JoseHeader;

      expect(() => {
        header = Reflect.construct(JoseHeader, [{ alg: "RS256", b64: false, crit: ["b64"] }]);
      }).not.toThrow();

      expect(header.certificateChain).toBeNull();
      expect(header.jsonWebKey).toBeNull();
      expect(header.parameters).toStrictEqual<JoseHeaderParameters>({ alg: "RS256", b64: false, crit: ["b64"] });
    });

    it("should set the JSON Web Key of the JOSE Header in the first access.", () => {
      const header: JoseHeader = Reflect.construct(JoseHeader, [parameters]);

      expect(header.jsonWebKey).toBeNull();
      expect(header.jsonWebKey).toBeNull();
    });

    it("should set the JSON Web Key of the JOSE Header.", () => {
      const header: JoseHeader = Reflect.construct(JoseHeader, [parameters]);
      expect(() => (header.jsonWebKey = null)).not.toThrow();
    });

    it("should set the X.509 Certificate Chain of the JOSE Header in the first access.", () => {
      const header: JoseHeader = Reflect.construct(JoseHeader, [parameters]);

      expect(header.certificateChain).toBeNull();
      expect(header.certificateChain).toBeNull();
    });

    it("should set the X.509 Certificate Chain of the JOSE Header.", () => {
      const header: JoseHeader = Reflect.construct(JoseHeader, [parameters]);
      expect(() => (header.certificateChain = null)).not.toThrow();
    });
  });
});
