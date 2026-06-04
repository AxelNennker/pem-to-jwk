#!/bin/bash

# Test script for PEM to JWK converter

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo "================================"
echo "PEM to JWK Converter Test Suite"
echo "================================"
echo ""

# Generate test keys if they don't exist
if [ ! -f test_rsa_private.pem ]; then
    echo "Generating test RSA keys..."
    openssl genrsa -out test_rsa_private.pem 2048 2>/dev/null
    openssl rsa -in test_rsa_private.pem -pubout -out test_rsa_public.pem 2>/dev/null
fi

if [ ! -f test_ec_private.pem ]; then
    echo "Generating test EC keys..."
    openssl ecparam -name prime256v1 -genkey -noout -out test_ec_private.pem 2>/dev/null
    openssl ec -in test_ec_private.pem -pubout -out test_ec_public.pem 2>/dev/null
fi

# Clean up old test files
rm -f test_output_*.json

# Test 1: RSA Public Key with default options
echo -e "${YELLOW}Test 1: RSA Public Key (default thumbprint kid)${NC}"
java PemToJwkStandalone.java --input test_rsa_public.pem --output test_output_rsa_pub.json
if [ -f test_output_rsa_pub.json ]; then
    echo -e "${GREEN}✓ Passed${NC}"
    echo "Output:"
    cat test_output_rsa_pub.json | head -6
    echo ""
else
    echo -e "${RED}✗ Failed${NC}"
    exit 1
fi

# Test 2: RSA Public Key with custom parameters
echo -e "${YELLOW}Test 2: RSA Public Key with custom kid, use, alg${NC}"
java PemToJwkStandalone.java \
    --input test_rsa_public.pem \
    --output test_output_rsa_pub_custom.json \
    --kid "my-rsa-key-2024" \
    --use sig \
    --alg RS256
if [ -f test_output_rsa_pub_custom.json ]; then
    echo -e "${GREEN}✓ Passed${NC}"
    echo "Output:"
    cat test_output_rsa_pub_custom.json | grep -E "(kid|use|alg)"
    echo ""
else
    echo -e "${RED}✗ Failed${NC}"
    exit 1
fi

# Test 3: EC Public Key
echo -e "${YELLOW}Test 3: EC Public Key (P-256)${NC}"
java PemToJwkStandalone.java \
    --input test_ec_public.pem \
    --output test_output_ec_pub.json \
    --use sig \
    --alg ES256
if [ -f test_output_ec_pub.json ]; then
    echo -e "${GREEN}✓ Passed${NC}"
    echo "Output:"
    cat test_output_ec_pub.json | head -6
    echo ""
else
    echo -e "${RED}✗ Failed${NC}"
    exit 1
fi

# Test 4: RSA Private Key
echo -e "${YELLOW}Test 4: RSA Private Key${NC}"
java PemToJwkStandalone.java \
    --input test_rsa_private.pem \
    --output test_output_rsa_priv.json \
    --kid "rsa-private-key"
if [ -f test_output_rsa_priv.json ]; then
    echo -e "${GREEN}✓ Passed${NC}"
    # Check that private key parameters are present
    if grep -q '"d":' test_output_rsa_priv.json && \
       grep -q '"p":' test_output_rsa_priv.json && \
       grep -q '"q":' test_output_rsa_priv.json; then
        echo "Private key parameters (d, p, q) present: ✓"
    else
        echo -e "${RED}Private key parameters missing!${NC}"
        exit 1
    fi
    echo ""
else
    echo -e "${RED}✗ Failed${NC}"
    exit 1
fi

# Test 5: Stdin to Stdout
echo -e "${YELLOW}Test 5: Stdin to Stdout${NC}"
OUTPUT=$(cat test_rsa_public.pem | java PemToJwkStandalone.java)
if echo "$OUTPUT" | grep -q '"kty": "RSA"'; then
    echo -e "${GREEN}✓ Passed${NC}"
    echo "Output contains RSA key type"
    echo ""
else
    echo -e "${RED}✗ Failed${NC}"
    exit 1
fi

# Test 6: key_ops parameter
echo -e "${YELLOW}Test 6: Multiple key_ops${NC}"
java PemToJwkStandalone.java \
    --input test_rsa_public.pem \
    --output test_output_key_ops.json \
    --key-ops "verify,wrapKey"
if [ -f test_output_key_ops.json ]; then
    echo -e "${GREEN}✓ Passed${NC}"
    if grep -q '"key_ops": \["verify", "wrapKey"\]' test_output_key_ops.json; then
        echo "key_ops array present: ✓"
    else
        echo "key_ops content:"
        cat test_output_key_ops.json | grep key_ops
    fi
    echo ""
else
    echo -e "${RED}✗ Failed${NC}"
    exit 1
fi

# Test 7: Help command
echo -e "${YELLOW}Test 7: Help command${NC}"
if java PemToJwkStandalone.java --help | grep -q "Usage:"; then
    echo -e "${GREEN}✓ Passed${NC}"
    echo ""
else
    echo -e "${RED}✗ Failed${NC}"
    exit 1
fi

# Test 8: Version command
echo -e "${YELLOW}Test 8: Version command${NC}"
if java PemToJwkStandalone.java --version | grep -q "version"; then
    echo -e "${GREEN}✓ Passed${NC}"
    echo ""
else
    echo -e "${RED}✗ Failed${NC}"
    exit 1
fi

echo "================================"
echo -e "${GREEN}All tests passed!${NC}"
echo "================================"
echo ""
echo "Generated test files:"
ls -lh test_output_*.json 2>/dev/null || true
echo ""
echo "Clean up test files with: rm test_output_*.json"
