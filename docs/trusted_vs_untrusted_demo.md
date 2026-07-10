# DAVINCI Prototype: Trusted vs Untrusted Demo

This document explains how to demonstrate the difference between trusted and untrusted attestation scenarios using the DAVINCI prototype.

## Overview

The DAVINCI prototype includes functionality to detect tampered evidence and report whether a system is trusted or not. This is demonstrated through two scenarios:

1. **Trusted Scenario**: All evidence is valid and untampered
2. **Untrusted Scenario**: Evidence has been tampered with

## Prerequisites

Before running the demos, ensure you have:

1. Rust toolchain installed
2. Python dependencies installed (`pip install -r requirements.txt`)
3. Services built (`make build`)
4. Attestation Manager and Verifier services running

## Running the Services

Start the required services in separate terminals:

```bash
# Terminal 1: Start Attestation Manager
make run-attestation-manager

# Terminal 2: Start Verifier
make run-verifier
```

## Running Individual Demos

### Trusted Demo

To run the trusted attestation demo:

```bash
make demo-trust
```

This will show a successful attestation where all evidence is valid and the system is reported as TRUSTED.

### Untrusted Demo

To run the untrusted attestation demo:

```bash
make demo-untrusted
```

This will show an attestation where evidence has been tampered with, and the system is reported as NOT TRUSTED.

## Running the Comparison Demo

To run both demos sequentially and see the comparison:

```bash
make demo-compare
```

This will run both the trusted and untrusted demos and provide a summary of the differences.

## How It Works

### Trusted Scenario

In the trusted scenario:
- All evidence (TPM quotes, SEV-SNP reports, runtime measurements) is valid
- The Verifier successfully validates all evidence
- The final trust decision is TRUSTED
- All components show as verified (✓)

### Untrusted Scenario

In the untrusted scenario:
- Evidence has been intentionally tampered with (contains "tampered" markers)
- The Verifier detects the tampered evidence
- The final trust decision is NOT TRUSTED
- Some components show as failed verification (✗)
- The explanation indicates which components failed

## Key Components Demonstrated

1. **Evidence Collection**: Shows how evidence is collected from different sources
2. **Evidence Normalization**: Demonstrates how evidence is normalized to a common format
3. **Evidence Storage**: Shows how evidence is stored in the Attestation Record Graph
4. **Evidence Verification**: Demonstrates how evidence is verified for integrity
5. **Trust Decision**: Shows how trust decisions are made based on verification results

## Modifying the Demo

To modify what constitutes "trusted" vs "untrusted" in the demo:

1. Edit [demo_trusted_vs_untrusted.py](file:///Users/gulshankumar/Desktop/snp-guard-main/davinci-prototype/demo/demo_trusted_vs_untrusted.py) to change how evidence is tampered
2. Edit [verifier/src/main.rs](file:///Users/gulshankumar/Desktop/snp-guard-main/davinci-prototype/verifier/src/main.rs) to change how evidence is verified
3. Rebuild the verifier service: `cd verifier && cargo build`

## Troubleshooting

If you encounter issues:

1. Ensure both services are running on ports 3030 and 3031
2. Check that no other processes are using these ports
3. Verify that Rust is properly installed and the environment is sourced
4. Check the service logs for any error messages

## Conclusion

The trusted vs untrusted demo effectively demonstrates the core functionality of the DAVINCI prototype:
- Collection and normalization of evidence from multiple sources
- Detection of tampered evidence
- Production of trust decisions based on verification results
- Clear reporting of which components passed or failed verification