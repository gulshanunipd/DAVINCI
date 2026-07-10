#!/usr/bin/env python3
"""
DAVINCI Trusted vs Untrusted Demo (cryptographically real).

Trusted run:   all evidence carries a valid RoT signature -> MRAL admits every
               layer -> AM exports a signed ARG -> Verifier accepts.
Untrusted run: the Guest measurement is tampered AFTER the RoT signed it -> MRAL
               Auth rejects it -> the Guest node never enters the ARG -> the
               Application node has no trust path to Platform -> Verifier rejects.

The decision is produced by real ECDSA verification + graph validation, NOT by
the session name.
"""

import sys
import time
from davinci_common import DavinciClient, make_evidence, print_verification


def run(is_untrusted: bool):
    label = "UNTRUSTED" if is_untrusted else "TRUSTED"
    session_id = f"{'untrusted' if is_untrusted else 'trusted'}_demo_{int(time.time())}"
    client = DavinciClient()

    print("=" * 64)
    print(f"DAVINCI {label} Attestation Demo   (session: {session_id})")
    print("=" * 64)

    # 1. Platform (TPM)
    print("\n1. Platform TPM evidence ...")
    r = client.send_boot(session_id, "platform", "tpm",
                         make_evidence("tpm", "platform_boot_measurement"))
    print(f"   AM: {r.get('status')}")

    # 2. Hypervisor (TPM)
    print("2. Hypervisor TPM evidence ...")
    r = client.send_boot(session_id, "hypervisor", "tpm",
                         make_evidence("tpm", "hypervisor_boot_measurement"))
    print(f"   AM: {r.get('status')}")

    # 3. Guest (SEV-SNP) — tampered in the untrusted run.
    print(f"3. Guest SEV-SNP evidence ...{'  (TAMPERED after RoT signature)' if is_untrusted else ''}")
    r = client.send_boot(session_id, "guest", "snp",
                         make_evidence("snp", "guest_vm_measurement", tamper=is_untrusted))
    print(f"   AM: {r.get('status')}")

    # 4. Runtime (IMA)
    print("4. Runtime IMA evidence ...")
    r = client.send_runtime(session_id,
                            make_evidence("ima", "ima_runtime_measurement"))
    print(f"   AM: {r.get('status')}")

    # 5. Verify with a fresh challenge.
    nonce = f"chal_{int(time.time()*1000)}"
    print(f"\n5. Verifying (challenge={nonce}) ...")
    result = client.verify(session_id, nonce)
    trusted = print_verification(result)

    print("\n" + "=" * 64)
    print(f"{label} demo complete — verifier returned {'TRUSTED' if trusted else 'NOT TRUSTED'}")
    print("=" * 64)
    return trusted


def main():
    is_untrusted = len(sys.argv) > 1 and sys.argv[1] == "untrusted"
    run(is_untrusted)


if __name__ == "__main__":
    main()
