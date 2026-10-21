#!/usr/bin/env python3
"""
DAVINCI Trusted vs Untrusted Demo — real Roots of Trust.

Each scenario power-cycles the emulated Arm platform into a boot profile, then
runs a full attestation round (challenge -> MRAL collect -> verify):

  good             reference images                         -> TRUSTED
  tampered-kernel  implant in the measured initramfs        -> NOT TRUSTED
                   (TPM PCR 9 differs from the reference)
  tampered-ta      backdoored workload TA (validly signed)  -> NOT TRUSTED
                   (OP-TEE TA memory/header hash differs)
  replay           good platform, but the verifier is
                   presented an already-used challenge      -> NOT TRUSTED

Usage: demo_trusted_vs_untrusted.py [good|tampered-kernel|tampered-ta|replay]
"""

import sys
import time

from davinci_common import DavinciClient, print_collection, print_verification

SCENARIOS = ("good", "tampered-kernel", "tampered-ta", "replay")


def run(scenario: str) -> bool:
    if scenario not in SCENARIOS:
        sys.exit(f"unknown scenario {scenario!r}; expected one of {SCENARIOS}")
    client = DavinciClient()
    profile = "good" if scenario == "replay" else scenario
    session_id = f"{scenario}_{int(time.time())}"

    print("=" * 72)
    print(f"DAVINCI attestation — scenario '{scenario}'   (session: {session_id})")
    print("=" * 72)

    print(f"\n1. Power-cycling the platform into profile '{profile}' (measured boot) ...")
    st = client.boot(profile)
    if not st.get("guest_ready"):
        print(f"   ✗ platform did not boot: {st}")
        return False
    print("   platform up")

    nonce = client.challenge()
    print(f"\n2. Verifier challenge c = {nonce[:16]}…")

    print("\n3. Attestation Manager collects evidence from the TPM and OP-TEE ...")
    print_collection(client.collect(session_id, nonce))

    if scenario == "replay":
        print("\n   (first verification consumes the challenge)")
        client.verify(session_id, nonce)
        print("   Replaying the same challenge and evidence ...")

    print("\n4. Verifying ...")
    trusted = print_verification(client.verify(session_id, nonce))

    print("\n" + "=" * 72)
    print(f"Scenario '{scenario}' — verifier returned {'TRUSTED' if trusted else 'NOT TRUSTED'}")
    print("=" * 72)
    return trusted


def main():
    run(sys.argv[1] if len(sys.argv) > 1 else "good")


if __name__ == "__main__":
    main()
