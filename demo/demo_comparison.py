#!/usr/bin/env python3
"""
DAVINCI Trusted vs Untrusted Comparison Demo.

Runs both scenarios in-process and prints a side-by-side summary. Requires the
PCE (3032), Attestation Manager (3030), and Verifier (3031) to be running.
"""

from demo_trusted_vs_untrusted import run


def main():
    print("=" * 80)
    print("DAVINCI PROTOTYPE: TRUSTED vs UNTRUSTED ATTESTATION COMPARISON")
    print("=" * 80)

    print("\n### SCENARIO 1: TRUSTED (all evidence authentic) ###\n")
    trusted_ok = run(is_untrusted=False)

    print("\n\n### SCENARIO 2: UNTRUSTED (guest evidence tampered) ###\n")
    untrusted_ok = run(is_untrusted=True)

    print("\n" + "=" * 80)
    print("COMPARISON SUMMARY")
    print("=" * 80)
    print(f"  Trusted scenario   -> verifier said: {'TRUSTED ✅' if trusted_ok else 'NOT TRUSTED ❌'}")
    print(f"  Untrusted scenario -> verifier said: {'TRUSTED ✅' if untrusted_ok else 'NOT TRUSTED ❌'}")
    expected = trusted_ok and not untrusted_ok
    print()
    if expected:
        print("  ✅ Correct: authentic evidence is trusted, tampered evidence is rejected.")
    else:
        print("  ⚠️  Unexpected outcome — check that all three services are running.")

    print("\nUnlike the earlier prototype, this decision comes from real ECDSA-P256")
    print("signature verification and graph validation, not the session name.")


if __name__ == "__main__":
    main()
