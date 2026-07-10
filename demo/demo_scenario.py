#!/usr/bin/env python3
"""
DAVINCI End-to-End Demo Scenario.

Full attestation workflow with real RoT-signed evidence:
  Platform (TPM) -> Hypervisor (TPM) -> Guest (SEV-SNP) -> Runtime (IMA)
  -> signed ARG export -> Verifier trust decision.

Requires PCE (3032), Attestation Manager (3030), Verifier (3031) running.
"""

import time
from davinci_common import DavinciClient, make_evidence, print_verification


def main():
    session_id = f"demo_session_{int(time.time())}"
    client = DavinciClient()

    print("=" * 64)
    print(f"DAVINCI End-to-End Attestation Demo   (session: {session_id})")
    print("=" * 64)

    steps = [
        ("platform", "tpm", "platform_boot_measurement", "1. Platform boot (TPM)"),
        ("hypervisor", "tpm", "hypervisor_boot_measurement", "2. Hypervisor launch (TPM)"),
        ("guest", "snp", "guest_vm_measurement", "3. Guest VM launch (SEV-SNP)"),
    ]
    for layer, source, seed, title in steps:
        print(f"\n{title} ...")
        r = client.send_boot(session_id, layer, source, make_evidence(source, seed))
        print(f"   AM: {r.get('status')}  node={r.get('node_id')}")

    print("\n4. Runtime integrity (IMA) ...")
    r = client.send_runtime(session_id, make_evidence("ima", "ima_runtime_measurement"))
    print(f"   AM: {r.get('status')}  node={r.get('node_id')}")

    nonce = f"chal_{int(time.time()*1000)}"
    print(f"\n5. Verifying complete attestation chain (challenge={nonce}) ...")
    result = client.verify(session_id, nonce)
    print_verification(result)

    print("\n" + "=" * 64)
    print("DAVINCI Demo Completed!")
    print("=" * 64)


if __name__ == "__main__":
    main()
