#!/usr/bin/env python3
"""
DAVINCI Trusted vs Untrusted Comparison Demo.

Runs every scenario of demo_trusted_vs_untrusted.py against the real platform
and prints a summary. Exits non-zero if any outcome is unexpected, so it also
serves as the end-to-end integration test. Requires the platform, PCE, AM and
Verifier running, and provisioning done (demo/provision.py).
"""

import sys

from demo_trusted_vs_untrusted import run

EXPECTED = {
    "good": True,
    "tampered-kernel": False,
    "tampered-ta": False,
    "replay": False,
}

WHY = {
    "good": "all RoT evidence authentic, fresh and matching reference values",
    "tampered-kernel": "TPM PCR 9 (initramfs) differs from the reference",
    "tampered-ta": "OP-TEE workload TA memory/header hash differs from the reference",
    "replay": "verifier rejects an already-used challenge",
}


def main():
    results = {}
    for scenario in EXPECTED:
        print(f"\n\n### SCENARIO: {scenario} ###\n")
        results[scenario] = run(scenario)

    print("\n" + "=" * 80)
    print("COMPARISON SUMMARY")
    print("=" * 80)
    ok = True
    for scenario, expected in EXPECTED.items():
        got = results[scenario]
        mark = "✅" if got == expected else "⚠️ "
        ok &= got == expected
        print(f"  {mark} {scenario:<16} -> {'TRUSTED' if got else 'NOT TRUSTED':<12} ({WHY[scenario]})")

    # Leave the platform in its good state.
    from davinci_common import DavinciClient
    DavinciClient().boot("good")

    print()
    print("  ✅ All outcomes as expected." if ok else "  ⚠️  Unexpected outcome — see the scenario output above.")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
