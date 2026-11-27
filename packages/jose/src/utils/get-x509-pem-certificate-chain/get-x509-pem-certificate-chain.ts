/**
 * Fetches an X.509 PEM Certificate Chain from the provided URL.
 *
 * @param url X.509 PEM Certificate Chain URL.
 * @returns X.509 PEM Certificate Chain.
 * @throws {Error} Failed to parse the X.509 PEM Certificate Chain from the provided URL.
 */
export async function getX509PemCertificateChainFromUrl(url: string): Promise<string[]> {
  const response = await globalThis.fetch(url);

  if (!response.ok) {
    throw new Error("Failed to parse the X.509 PEM Certificate Chain from the provided URL.");
  }

  const pemCertificateChain = await response.text();

  const pemCertificates = pemCertificateChain.match(
    /^-----BEGIN CERTIFICATE-----\r?\n((?:(?!-----).*\r?\n)*)-----END CERTIFICATE-----$/gmu,
  );

  if (pemCertificates === null || pemCertificates.length === 0) {
    throw new Error("Failed to parse the X.509 PEM Certificate Chain from the provided URL.");
  }

  return pemCertificates.map((pemCertificate) =>
    pemCertificate.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", ""),
  );
}
