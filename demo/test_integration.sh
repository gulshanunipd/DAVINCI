#!/usr/bin/env bash
# DAVINCI end-to-end integration test against the real Roots of Trust.
#
# Needs the platform container (make platform) and the three services
# (make run-pce / run-attestation-manager / run-verifier) running. Provisions
# the RoTs and reference values, then runs every trusted/untrusted scenario
# and fails if any trust decision is not the expected one.
set -euo pipefail
cd "$(dirname "$0")"

check() {
  if curl -sf "$2" > /dev/null; then echo "  ✓ $1"; else echo "  ✗ $1 not reachable at $2"; exit 1; fi
}
echo "Checking components..."
check "platform controller" "http://localhost:4000/status"
check "TPM collector"       "http://localhost:4010/enroll"
check "OP-TEE collector"    "http://localhost:4020/cgi-bin/attest?op=pubkey"
check "PCE"                 "http://localhost:3032/health"
check "Attestation Manager" "http://localhost:3030/pubkey"
check "Verifier"            "http://localhost:3031/health"

echo; echo "Provisioning (enrollment + reference values)..."
python3 provision.py

echo; echo "Running trusted / untrusted scenarios..."
python3 demo_comparison.py
