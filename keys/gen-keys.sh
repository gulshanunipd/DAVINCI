#!/usr/bin/env bash
# Generate the Attestation Manager key pair (sk_AM / pk_AM, ECDSA-P256): the
# AM signs ARG edges and the attestation output with it, and pk_AM is the
# Verifier's trust anchor τ (D3 Setup).
#
# Root-of-Trust keys are NOT generated here: they live in the RoTs themselves
# (TPM EK/AK, OP-TEE attestation key) and are trusted through enrollment
# (POST /mral/enroll). keys/rot/ receives the TPM manufacturer CA published by
# the platform, and keys/enrollment.json the enrolled RoT keys.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p rot
if [ -f am_priv.pem ]; then
  echo "AM key already present ($(pwd)/am_priv.pem)"
  exit 0
fi
openssl ecparam -name prime256v1 -genkey -noout -out am_priv.pem
openssl ec -in am_priv.pem -pubout -out am_pub.pem 2>/dev/null
echo "Generated am_priv.pem / am_pub.pem in $(pwd)"
