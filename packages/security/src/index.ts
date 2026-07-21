import { createHmac, timingSafeEqual } from "node:crypto";

const githubSignaturePattern = /^sha256=([0-9a-f]{64})$/;

export function verifyGitHubWebhookSignature(
  rawBody: Uint8Array | string,
  signatureHeader: string | null,
  secret: string
): boolean {
  const match = signatureHeader?.match(githubSignaturePattern);
  if (match === undefined || match === null) return false;
  const suppliedHex = match[1];
  if (suppliedHex === undefined) return false;

  const expected = createHmac("sha256", secret).update(rawBody).digest();
  const supplied = Buffer.from(suppliedHex, "hex");
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}
