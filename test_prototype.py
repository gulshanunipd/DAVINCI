#!/usr/bin/env python3
"""
End-to-end test of the DAVINCI prototype.

Runs demo/test_integration.sh: provisioning of the two Roots of Trust (TPM 2.0
and OP-TEE) followed by every trusted/untrusted scenario. Exits non-zero if
any component is unreachable or any trust decision is unexpected.
"""

import os
import subprocess
import sys


def main():
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo", "test_integration.sh")
    sys.exit(subprocess.run(["bash", script]).returncode)


if __name__ == "__main__":
    main()
