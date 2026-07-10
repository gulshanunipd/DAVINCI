#!/bin/bash

# DAVINCI Runtime Attestation Demo
# This script demonstrates the runtime attestation workflow with IMA/EVM

echo "DAVINCI Runtime Attestation Demo"
echo "==============================="

# Start the Attestation Manager service in the background
echo "1. Starting Attestation Manager service..."
cd ../attestation-manager
cargo run & 
ATT_MANAGER_PID=$!
cd ../demo

# Wait a moment for the service to start
sleep 3

# Simulate collecting IMA measurements
echo "2. Simulating IMA measurements..."

# Send runtime evidence to attestation manager
echo "3. Sending runtime evidence to Attestation Manager..."
curl -X POST http://localhost:3030/attest/runtime \
  -H "Content-Type: application/json" \
  -d '{
    "evidence": "{\"path\": \"/bin/ls\", \"hash\": \"abc123hash\", \"template_hash\": \"def456template\", \"timestamp\": \"2023-01-01T00:01:00Z\"}"
  }'

echo ""

curl -X POST http://localhost:3030/attest/runtime \
  -H "Content-Type: application/json" \
  -d '{
    "evidence": "{\"path\": \"/bin/cat\", \"hash\": \"xyz789hash\", \"template_hash\": \"uvw012template\", \"timestamp\": \"2023-01-01T00:01:01Z\"}"
  }'

echo ""

curl -X POST http://localhost:3030/attest/runtime \
  -H "Content-Type: application/json" \
  -d '{
    "evidence": "{\"path\": \"/etc/passwd\", \"hash\": \"invalidhash\", \"template_hash\": \"invalidtemplate\", \"timestamp\": \"2023-01-01T00:01:02Z\"}"
  }'

echo ""

# Retrieve the ARG
echo "4. Retrieving Attestation Record Graph..."
curl -X GET http://localhost:3030/arg/test_session

echo ""
echo "5. Runtime attestation demo completed!"

# Kill the attestation manager service
kill $ATT_MANAGER_PID