# PEM to JWK Converter

A Java command-line application that converts PEM-encoded RSA and EC keys (public or private) to JSON Web Key (JWK) format according to RFC 7517, with RFC 7638 thumbprint support.

## Features

- ✅ Supports RSA public and private keys
- ✅ Supports EC (Elliptic Curve) public keys
- ✅ Automatic JWK thumbprint calculation (RFC 7638)
- ✅ Custom Key ID (kid) support
- ✅ Optional JWK parameters: use, alg, key_ops
- ✅ Read from stdin or file
- ✅ Write to stdout or file
- ✅ Zero dependencies (standalone version)
- ✅ Works with Java 11+

## Requirements

- Java 11 or higher (17+ recommended)
- No external dependencies required for standalone version

## Quick Start

The standalone version requires no compilation and works directly:
```bash
# Make the wrapper script executable
chmod +x pem-to-jwk

# Run directly
./pem-to-jwk --input key.pem
```

Or use Java directly:
```bash
java PemToJwkStandalone.java --input key.pem --output key.jwk
```

## Usage

### Basic Examples
```bash
# Convert from file to stdout
./pem-to-jwk --input key.pem

# Convert from stdin to file
cat key.pem | ./pem-to-jwk --output key.jwk

# With custom kid and use parameter
./pem-to-jwk -i key.pem -o key.jwk --kid mykey123 --use sig

# Or use Java directly
java PemToJwkStandalone.java --input key.pem --alg RS256 --use sig
```

### Command-Line Options
```
Options:
  --input, -i FILE    Read PEM key from FILE (default: stdin)
  --output, -o FILE   Write JWK to FILE (default: stdout)
  --kid VALUE         Set Key ID (default: RFC 7638 thumbprint)
  --use VALUE         Set 'use' parameter: 'sig' or 'enc'
  --alg VALUE         Set 'alg' parameter (e.g., RS256, ES256)
  --key-ops VALUES    Set 'key_ops' (comma-separated)
  --help, -h          Show help message
  --version, -v       Show version information
```

### Supported Key Types

- **RSA Public Keys**: PKCS#1 or X.509 format
- **RSA Private Keys**: PKCS#1 or PKCS#8 format (CRT format required)
- **EC Public Keys**: X.509 format (P-256, P-384, P-521 curves)
- **EC Private Keys**: Not supported (use public key instead)

### Example Output

Input (RSA public key):
```pem
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Z3VS...
-----END PUBLIC KEY-----
```

Output (JWK):
```json
{
  "kty": "RSA",
  "n": "0Z3VSjP...",
  "e": "AQAB",
  "kid": "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
  "use": "sig"
}
```

## Testing

The project includes a comprehensive test suite:
```bash
# Run all tests
./test.sh
```

### Generate Test Keys
```bash
# RSA keys
openssl genrsa -out test_rsa_private.pem 2048
openssl rsa -in test_rsa_private.pem -pubout -out test_rsa_public.pem

# EC keys
openssl ecparam -name prime256v1 -genkey -noout -out test_ec_private.pem
openssl ec -in test_ec_private.pem -pubout -out test_ec_public.pem
```

### Example Tests
```bash
# Test with RSA public key
./pem-to-jwk --input test_rsa_public.pem --use sig

# Test with EC public key
./pem-to-jwk --input test_ec_public.pem --alg ES256

# Test with RSA private key
./pem-to-jwk --input test_rsa_private.pem --output rsa_jwk.json

# Test stdin to stdout
cat test_rsa_public.pem | ./pem-to-jwk
```

## RFC Compliance

- **RFC 7517**: JSON Web Key (JWK)
- **RFC 7638**: JSON Web Key (JWK) Thumbprint

## Implementation Details

### JWK Thumbprint (RFC 7638)

The thumbprint is calculated by:
1. Creating a canonical JSON representation with only required members
2. Ordering keys lexicographically (e.g., for RSA: "e", "kty", "n")
3. Computing SHA-256 hash of the UTF-8 encoded JSON
4. Base64url encoding the hash (without padding)

### Key Format Support

**RSA Keys:**
- Public keys: Extracts modulus (n) and exponent (e)
- Private keys: Extracts all CRT parameters (n, e, d, p, q, dp, dq, qi)

**EC Keys:**
- Public keys: Extracts curve name (crv), x and y coordinates
- Private keys: Currently not supported (requires point derivation)

## Limitations

- EC private key conversion requires EC point derivation from the private scalar
- Only P-256, P-384, and P-521 curves are supported for EC keys
- RSA private keys must be in CRT (Chinese Remainder Theorem) format

## Project Structure
```
pem-to-jwt/
├── PemToJwkStandalone.java   # Main standalone application (no deps)
├── pem-to-jwk                 # Convenience wrapper script
├── test.sh                    # Comprehensive test suite
└── README.md                  # This file
```

## License

This is a utility tool provided as-is for educational and practical purposes.
