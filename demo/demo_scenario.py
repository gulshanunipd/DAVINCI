#!/usr/bin/env python3
"""
DAVINCI End-to-End Demo Scenario.

One attestation round against the real platform, showing each stage:

  Verifier challenge
  -> MRAL Collect/Auth: TPM 2.0 quote (Platform PCR 0-7, Hypervisor PCR 8-9)
                        OP-TEE PTA evidence (Guest: TEE OS, Application: TA)
  -> PCE Transform (suppress / abstract / pseudonymize)
  -> AMC + ARG with AM-signed edges
  -> signed output -> Verifier trust decision

Requires the platform, PCE (3032), AM (3030), Verifier (3031) running and
provisioning done (demo/provision.py).
"""

import json
import time

from davinci_common import DavinciClient, node_evidence, print_collection, print_verification


def main():
    session_id = f"demo_session_{int(time.time())}"
    client = DavinciClient()

    print("=" * 72)
    print(f"DAVINCI End-to-End Attestation Demo   (session: {session_id})")
    print("=" * 72)

    nonce = client.challenge()
    print(f"\n1. Verifier issues challenge c = {nonce[:16]}…")

    print("\n2. Attestation Manager: Collect (MRAL) -> Transform (PCE) -> Attest (AMC/ARG)")
    print_collection(client.collect(session_id, nonce))

    print("\n3. Privacy-transformed evidence in the ARG (what the verifier sees):")
    for layer, ev in node_evidence(client.arg(session_id)).items():
        shown = {k: (v[:20] + "…" if isinstance(v, str) and len(v) > 24 else v)
                 for k, v in ev.items() if k not in ("pcrs", "clock_info")}
        print(f"   {layer}: {json.dumps(shown, ensure_ascii=False)}")

    print("\n4. Verifier: output signature, freshness, ϕ_G, reference values")
    print_verification(client.verify(session_id, nonce))

    print("\n" + "=" * 72)
    print("DAVINCI Demo Completed!")
    print("=" * 72)


if __name__ == "__main__":
    main()
