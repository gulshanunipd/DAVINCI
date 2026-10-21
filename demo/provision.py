#!/usr/bin/env python3
"""
DAVINCI provisioning: enroll the Roots of Trust and record reference values.

  1. Boot the platform in its known-good profile.
  2. Enroll the RoTs through the Attestation Manager (POST /mral/enroll):
       TPM    EK certificate -> manufacturer CA, AK profile, credential activation
       OP-TEE attestation-key registration
  3. Reference values, written to reference/reference-values.json for the
     Verifier:
       TPM    expected PCR 0-9, computed by replaying the measured boot of the
              platform images (vendor reference manifest, GET /reference)
       OP-TEE runtime hashes of the TEE core and workload TA, taken from a
              verified collection on the known-good platform (endorsed at
              provisioning time)

Requires the platform (4000/4010/4020), PCE (3032) and AM (3030) running.
"""

import json
import os
import secrets
import sys
import time

from davinci_common import DavinciClient, node_evidence

REFERENCE = os.environ.get(
    "DAVINCI_REFERENCE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reference", "reference-values.json"),
)


def main():
    c = DavinciClient()

    print("1. Booting platform (profile: good) ...")
    st = c.boot("good")
    if not st.get("guest_ready"):
        sys.exit(f"   platform did not boot: {st}")
    print("   platform up: TF-A -> OP-TEE -> U-Boot -> Linux, measured into the TPM")

    print("2. Enrolling Roots of Trust ...")
    enr = c.enroll()
    for r in enr.get("rots", []):
        print(f"   {'✓' if r['verified'] else '✗'} {r['rot']}: {r['error'] or ''}")
        for chk in r.get("checks", []):
            print(f"       · {chk}")
    if not enr.get("enrolled"):
        sys.exit("   enrollment failed")

    print("3. Recording reference values ...")
    tpm_ref = c.platform_reference()
    sid = f"provisioning-{int(time.time())}"
    resp = c.collect(sid, secrets.token_hex(32))
    if resp.get("status") != "success":
        sys.exit(f"   reference collection failed: {resp}")
    ev = node_evidence(c.arg(sid))

    measured = {**ev["Platform"]["pcrs"], **ev["Hypervisor"]["pcrs"]}
    if measured != tpm_ref["pcrs"]:
        sys.exit("   measured PCRs differ from the image-derived reference: platform not in a known-good state")
    print("   TPM: image-derived PCR 0-9 reference matches the measured good boot")

    reference = {
        "generated_at": int(time.time()),
        "tpm": {"bank": "sha256", "pcrs": tpm_ref["pcrs"], "source": tpm_ref["source"]},
        "optee": {
            "tee_core_hash": ev["Guest"]["tee_core_hash"],
            "ta_uuid": ev["Application"]["ta_uuid"],
            "ta_memory_hash": ev["Application"]["ta_memory_hash"],
            "ta_shdr_digest": ev["Application"]["ta_shdr_digest"],
            "source": "verified OP-TEE evidence from the known-good platform at provisioning",
        },
    }
    os.makedirs(os.path.dirname(REFERENCE), exist_ok=True)
    with open(REFERENCE, "w") as f:
        json.dump(reference, f, indent=2)
    print(f"   OP-TEE: TEE core {reference['optee']['tee_core_hash'][:16]}…, "
          f"TA {reference['optee']['ta_memory_hash'][:16]}…")
    print(f"   written {os.path.normpath(REFERENCE)}")


if __name__ == "__main__":
    main()
