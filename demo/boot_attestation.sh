#!/bin/bash

# DAVINCI Boot Attestation Demo
# This script demonstrates the boot-time attestation workflow

echo "DAVINCI Boot Attestation Demo"
echo "============================"

# Start the Attestation Manager service in the background
echo "1. Starting Attestation Manager service..."
cd ../attestation-manager
cargo run & 
ATT_MANAGER_PID=$!
cd ../demo

# Wait a moment for the service to start
sleep 3

# Simulate collecting platform TPM evidence
echo "2. Collecting platform TPM evidence..."
python3 ../mral-adapters/tpm-adapter/tpm_adapter.py > /dev/null

# Send platform evidence to attestation manager
echo "3. Sending platform evidence to Attestation Manager..."
curl -X POST http://localhost:3030/attest/boot \
  -H "Content-Type: application/json" \
  -d '{
    "layer": "platform",
    "source": "tpm",
    "evidence": "{\"quote\": {\"pcrs\": {\"0\": \"abc123\", \"1\": \"def456\"}, \"nonce\": \"test_nonce\", \"timestamp\": \"2023-01-01T00:00:00Z\"}, \"signature\": \"quote_signature\"}"
  }'

echo ""

# Simulate collecting hypervisor evidence
echo "4. Collecting hypervisor evidence..."

# Send hypervisor evidence to attestation manager
echo "5. Sending hypervisor evidence to Attestation Manager..."
curl -X POST http://localhost:3030/attest/boot \
  -H "Content-Type: application/json" \
  -d '{
    "layer": "hypervisor",
    "source": "tpm",
    "evidence": "{\"quote\": {\"pcrs\": {\"0\": \"xyz789\", \"1\": \"uvw012\"}, \"nonce\": \"test_nonce2\", \"timestamp\": \"2023-01-01T00:00:01Z\"}, \"signature\": \"hypervisor_signature\"}"
  }'

echo ""

# Simulate collecting guest evidence (SEV-SNP)
echo "6. Collecting guest evidence (SEV-SNP)..."

# Send guest evidence to attestation manager
echo "7. Sending guest evidence to Attestation Manager..."
curl -X POST http://localhost:3030/attest/boot \
  -H "Content-Type: application/json" \
  -d '{
    "layer": "guest",
    "source": "snp",
    "evidence": "{\"platform_info\": \"AMD EPYC 7xx3 Series\", \"measurement\": \"vm_measurement_hash\", \"guest_policy\": \"0x30000\", \"signature\": \"snp_signature\", \"timestamp\": \"2023-01-01T00:00:02Z\"}"
  }'

echo ""

# Retrieve the ARG
echo "8. Retrieving Attestation Record Graph..."
curl -X GET http://localhost:3030/arg/test_session

echo ""
echo "9. Boot attestation demo completed!"

# Kill the attestation manager service
kill $ATT_MANAGER_PID