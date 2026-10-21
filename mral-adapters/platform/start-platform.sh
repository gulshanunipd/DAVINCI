#!/usr/bin/env bash
# Entry point of the DAVINCI platform container.
set -euo pipefail
STATE=/var/lib/davinci
mkdir -p "$STATE/tpm" "$STATE/tee" "$STATE/ta" /trust

# Manufacture the TPM once: EK + EK certificate signed by the swtpm local CA
# (the "TPM manufacturer"). State persists in the volume, so enrollment holds
# across container restarts.
if [ ! -s "$STATE/tpm/tpm2-00.permall" ]; then
  swtpm_setup --tpm2 --tpmstate "$STATE/tpm" --create-ek-cert --create-platform-cert \
              --pcr-banks sha256 --overwrite --display
  rm -rf "$STATE/localca" && cp -r /var/lib/swtpm-localca "$STATE/localca"
fi

# Publish the manufacturer CA out of band: this is the trust anchor the
# Attestation Manager uses to validate EK certificates (mounted to keys/rot/).
cp "$STATE/localca/swtpm-localca-rootca-cert.pem" /trust/tpm-manufacturer-root.pem
cp "$STATE/localca/issuercert.pem" /trust/tpm-manufacturer-issuer.pem

swtpm socket --tpm2 --tpmstate dir="$STATE/tpm" \
  --server type=tcp,port=2321,bindaddr=127.0.0.1 \
  --ctrl type=tcp,port=2322,bindaddr=127.0.0.1 \
  --flags not-need-init --log file="$STATE/swtpm.log" &

python3 /opt/davinci/tpm-adapter/tpm_adapter.py &
python3 /opt/davinci/platform/controller.py &
wait -n
