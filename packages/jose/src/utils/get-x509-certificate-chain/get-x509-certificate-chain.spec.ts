import { X509Certificate } from "node:crypto";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { getX509CertificateChain } from "./get-x509-certificate-chain.ts";

const fetchMock = vi.fn<typeof globalThis.fetch>();

describe("getX509CertificateChain()", () => {
  const pemCertificates: string[] = [
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
  ];

  const pemCertificateChain = pemCertificates
    .map((pemCertificate) => `-----BEGIN CERTIFICATE-----\n${pemCertificate}\n-----END CERTIFICATE-----\n`)
    .join("");

  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-12T00:00:00Z"));
  });

  afterEach(() => {
    vi.clearAllTimers();
    vi.useRealTimers();
    vi.unstubAllGlobals();
    vi.resetAllMocks();
  });

  it('should return null when no "x5u" or "x5c" parameter is found at the provided parameters.', async () => {
    await expect(getX509CertificateChain({})).resolves.toBeNull();
  });

  it("should throw when providing an invalid X.509 Certificate.", async () => {
    const error = new Error("One or more X.509 Certificates is invalid.");
    await expect(getX509CertificateChain({ x5c: ["0123456789abcdef"] })).rejects.toThrow(error);
  });

  it("should throw when one or more X.509 Certificates are not yet valid.", async () => {
    vi.setSystemTime(new Date("2024-01-01T00:00:00Z"));

    const error = new Error("One or more X.509 Certificates are not yet valid.");
    await expect(getX509CertificateChain({ x5c: pemCertificates })).rejects.toThrow(error);
  });

  it("should throw when one or more X.509 Certificates are expired.", async () => {
    vi.setSystemTime(new Date("2028-01-01T00:00:00Z"));

    const error = new Error("One or more X.509 Certificates are expired.");
    await expect(getX509CertificateChain({ x5c: pemCertificates })).rejects.toThrow(error);
  });

  it("should throw when one or more X.509 Certificates were not signed by an X.509 Certificate in the chain.", async () => {
    const error = new Error("Invalid X.509 Certificate Chain.");
    await expect(getX509CertificateChain({ x5c: [pemCertificates[0]!, pemCertificates[2]!] })).rejects.toThrow(error);
  });

  it('should throw when the provided "x5t" parameter does not match the SHA-1 Fingerprint of the Certificate.', async () => {
    const error = new Error("Mismatching X.509 Certificate SHA-1 Thumbprint.");
    await expect(getX509CertificateChain({ x5c: pemCertificates, x5t: "0123456789abcdef" })).rejects.toThrow(error);
  });

  it('should throw when the provided "x5t#S256" parameter does not match the SHA-256 Fingerprint of the Certificate.', async () => {
    const error = new Error("Mismatching X.509 Certificate SHA-256 Thumbprint.");
    await expect(getX509CertificateChain({ x5c: pemCertificates, "x5t#S256": "0123456789abcdef" })).rejects.toThrow(
      error,
    );
  });

  it('should return the X.509 Certificates from the "x5u" parameter.', async () => {
    let certificateChain!: X509Certificate[] | null;

    fetchMock.mockResolvedValueOnce({ ok: true, status: 200, text: async () => pemCertificateChain } as Response);

    await expect(
      (async () => {
        certificateChain = await getX509CertificateChain({
          x5t: "tKL6B4sJGgaVlhGEUwchEOJTA50",
          x5u: "https://certificate.example.com",
        });
      })(),
    ).resolves.not.toThrow();

    expect(certificateChain).toHaveLength(3);
    expect(certificateChain).toSatisfy((value: unknown[]) =>
      value.every((certificate) => certificate instanceof X509Certificate),
    );
  });

  it('should return the X.509 Certificates from the "x5c" parameter.', async () => {
    let certificateChain!: X509Certificate[] | null;

    await expect(
      (async () => {
        certificateChain = await getX509CertificateChain({
          x5c: pemCertificates,
          "x5t#S256": "hRYOcUfJLh-Md6KzaOTdk9lv8Q8lhvZh6ucIqd3GaG0",
        });
      })(),
    ).resolves.not.toThrow();

    expect(certificateChain).toHaveLength(3);
    expect(certificateChain).toSatisfy((value: unknown[]) =>
      value.every((certificate) => certificate instanceof X509Certificate),
    );
  });
});
