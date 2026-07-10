#!/usr/bin/env bash
# Generate ECDSA-P256 key pairs for DAVINCI: one Attestation Manager (AM) key
# and one per Root-of-Trust source (the "trusted material" tm_r of D3 s9).
# Private RoT keys simulate the hardware-protected sk_r; public keys are the
# manufacturer-certified pk_r the MRAL uses to check Auth (D3 Eq. 5).
set -euo pipefail
cd "$(dirname "$0")"
gen() {
  local name="$1"
  openssl ecparam -name prime256v1 -genkey -noout -out "${name}_priv.pem"
  openssl ec -in "${name}_priv.pem" -pubout -out "${name}_pub.pem" 2>/dev/null
  echo "  generated ${name}_priv.pem / ${name}_pub.pem"
}
echo "Generating DAVINCI keys (ECDSA-P256)..."
gen am
for src in tpm snp tdx cca ima; do gen "rot_${src}"; done
echo "Done. Keys in $(pwd)"
