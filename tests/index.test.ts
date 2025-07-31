import forge from "node-forge";
import { validatePrivateKey } from "../src/index";
import { PrivateKeyValidationError } from "../src/types";

const generateRsaKey = (): string => {
  const keypair = forge.pki.rsa.generateKeyPair(512);
  return forge.pki.privateKeyToPem(keypair.privateKey);
};

describe("validatePrivateKey", () => {
  it("rejects empty string", () => {
    const res = validatePrivateKey("");
    expect(res.isValid).toBe(false);
    expect(res.errorType).toBe(PrivateKeyValidationError.CANT_BE_EMPTY);
  });

  it("rejects invalid header", () => {
    const validRsa = generateRsaKey();
    const invalidHeaderKey = validRsa.replace(
      /^-----BEGIN.*PRIVATE KEY-----/,
      "-----BEGIN INVALID KEY-----",
    );
    const res = validatePrivateKey(invalidHeaderKey);
    expect(res.isValid).toBe(false);
    expect(res.errorType).toBe(PrivateKeyValidationError.INVALID_HEADER);
  });

  it("rejects invalid footer", () => {
    const validRsa = generateRsaKey();

    const lines = validRsa.trim().split("\n");
    lines[lines.length - 1] = "-----END INVALID KEY-----";
    const invalidFooterKey = lines.join("\n");

    const res = validatePrivateKey(invalidFooterKey);
    expect(res.isValid).toBe(false);
    expect(res.errorType).toBe(PrivateKeyValidationError.INVALID_FOOTER);
  });

  it("rejects corrupted body", () => {
    const corrupted = `
-----BEGIN RSA PRIVATE KEY-----
@@@INVALIDBASE64@@@
-----END RSA PRIVATE KEY-----
`.trim();
    const res = validatePrivateKey(corrupted);
    expect(res.isValid).toBe(false);
    expect(res.errorType).toBe(PrivateKeyValidationError.INVALID_BODY_ERROR);
  });

  it("accepts valid RSA private key", () => {
    const rsaKey = generateRsaKey();
    const res = validatePrivateKey(rsaKey);
    expect(res.isValid).toBe(true);
    expect(res.message).toBe("Valid private key.");
    expect(res.errorType).toBeUndefined();
  });
});
