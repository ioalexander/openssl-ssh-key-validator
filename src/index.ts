import forge from "node-forge";
import { PrivateKeyValidationError, PrivateKeyValidationResult } from "./types";

export const validatePrivateKey = (pem: string): PrivateKeyValidationResult => {
  if (!pem.trim()) {
    return {
      isValid: false,
      message: "Private key cannot be empty.",
      errorType: PrivateKeyValidationError.CANT_BE_EMPTY,
    };
  }

  const lines = pem.trim().split(/\r?\n/);
  const header = lines[0];
  const footer = lines[lines.length - 1].trim();

  const validHeaders = [
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
  ];

  const validFooters = validHeaders.map((h) => h.replace("BEGIN", "END"));

  if (!validHeaders.includes(header)) {
    return {
      isValid: false,
      message: "Invalid private key header.",
      errorType: PrivateKeyValidationError.INVALID_HEADER,
      errorPosition: { line: 1, character: 1 },
    };
  }

  if (!validFooters.includes(footer)) {
    return {
      isValid: false,
      message: "Invalid private key footer.",
      errorType: PrivateKeyValidationError.INVALID_FOOTER,
      errorPosition: { line: lines.length, character: 1 },
    };
  }

  try {
    const pems = forge.pem.decode(pem);
    if (pems.length === 0) {
      throw new Error("No PEM blocks found");
    }

    const keyPem = pems.find((block) =>
      [
        "PRIVATE KEY",
        "RSA PRIVATE KEY",
        "EC PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
        "DSA PRIVATE KEY",
      ].includes(block.type),
    );

    if (!keyPem) {
      return {
        isValid: false,
        message: "No valid private key PEM block found.",
        errorType: PrivateKeyValidationError.INVALID_HEADER,
      };
    }

    if (keyPem.type === "ENCRYPTED PRIVATE KEY") {
      return {
        isValid: false,
        message: "Encrypted private keys are not supported.",
        errorType: PrivateKeyValidationError.INVALID_BODY_ERROR,
      };
    }

    const derBytes = forge.util.createBuffer(keyPem.body);
    let privateKey;

    if (
      keyPem.type === "RSA PRIVATE KEY" ||
      keyPem.type === "EC PRIVATE KEY" ||
      keyPem.type === "PRIVATE KEY"
    ) {
      privateKey = forge.pki.privateKeyFromAsn1(forge.asn1.fromDer(derBytes));
    } else if (keyPem.type === "DSA PRIVATE KEY") {
      return {
        isValid: true,
        message: "Valid DSA private key (basic validation).",
      };
    } else {
      return {
        isValid: false,
        message: `Unsupported private key type: ${keyPem.type}`,
        errorType: PrivateKeyValidationError.INVALID_HEADER,
      };
    }

    if (!privateKey) {
      throw new Error("Failed to parse private key");
    }

    return {
      isValid: true,
      message: "Valid private key.",
    };
  } catch {
    return {
      isValid: false,
      message: "Invalid private key format or corrupted data.",
      errorType: PrivateKeyValidationError.INVALID_BODY_ERROR,
    };
  }
};
