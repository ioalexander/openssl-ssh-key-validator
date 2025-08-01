# openssl-ssh-key-validator

Validate SSL/TLS private keys (RSA, EC, DSA) in PEM format with detailed error reporting.

## Features

- Supports multiple private key formats:
  - PKCS#8 (-----BEGIN PRIVATE KEY-----)
  - PKCS#1 RSA (-----BEGIN RSA PRIVATE KEY-----)
  - EC (-----BEGIN EC PRIVATE KEY-----)
  - DSA (-----BEGIN DSA PRIVATE KEY-----)
- Validates headers and footers
- Checks base64 integrity of the key body
- Detects corrupted or invalid keys
- Returns detailed error types and positions for easier debugging

## Installation

```bash
npm add openssl-ssh-key-validator
# or
yarn add openssl-ssh-key-validator
```

## Usage

```typescript
import { validatePrivateKey } from "openssl-ssh-key-validator";

const pem = `-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBALe3UMkTqyLZCNLoiOdVX0k+/9VFpLcdlHk...
-----END RSA PRIVATE KEY-----`;

const result = validatePrivateKey(pem);

if (result.isValid) {
  console.log("Valid private key.");
} else {
  console.error("Validation error:", result.errorType);
  console.error(result.message);
  if (result.errorPosition) {
    console.error(
      `At line ${result.errorPosition.line}, char ${result.errorPosition.character}`,
    );
  }
}
```

## Development

```
yarn install
yarn test
```

## Notes

- Encrypted private keys are currently not supported.
- Key validation uses node-forge internally for ASN.1 and PEM decoding.
