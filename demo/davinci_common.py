#!/usr/bin/env python3
"""
Shared helpers for DAVINCI demos.

The demos no longer fabricate evidence. They drive the real flow:

  verifier  GET  /challenge          fresh single-use challenge c
  AM        POST /attest/collect     MRAL pulls TPM + OP-TEE evidence bound to c,
                                     verifies it, PCE-transforms it, builds the ARG
  verifier  POST /verify             signed output + ϕ_G + reference values

and use the platform controller (test harness) to power-cycle the emulated
platform into a good or tampered boot profile.
"""

import json
import os
import urllib.error
import urllib.request

AM_URL = os.environ.get("ATTESTATION_MANAGER_URL", "http://localhost:3030")
VERIFIER_URL = os.environ.get("VERIFIER_URL", "http://localhost:3031")
PLATFORM_URL = os.environ.get("PLATFORM_URL", "http://localhost:4000")


def _request(url, payload=None, timeout=60):
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"},
        method="GET" if payload is None else "POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode())
        except ValueError:
            return {"error": f"HTTP {e.code}"}
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}


class DavinciClient:
    def __init__(self, am_url=AM_URL, ver_url=VERIFIER_URL, platform_url=PLATFORM_URL):
        self.am_url, self.ver_url, self.platform_url = am_url, ver_url, platform_url

    # platform harness
    def boot(self, profile):
        return _request(f"{self.platform_url}/boot", {"profile": profile}, timeout=240)

    def platform_reference(self):
        return _request(f"{self.platform_url}/reference")

    # attestation manager
    def enroll(self):
        return _request(f"{self.am_url}/mral/enroll", {})

    def collect(self, session_id, nonce):
        return _request(f"{self.am_url}/attest/collect", {"session_id": session_id, "nonce": nonce})

    def arg(self, session_id):
        r = _request(f"{self.am_url}/arg/{session_id}")
        return json.loads(r["arg"]) if "arg" in r else {}

    # verifier
    def challenge(self):
        return _request(f"{self.ver_url}/challenge")["nonce"]

    def verify(self, session_id, nonce):
        return _request(f"{self.ver_url}/verify", {"session_id": session_id, "nonce": nonce})


def node_evidence(arg):
    """layer -> parsed (privacy-transformed) evidence of that layer's node."""
    out = {}
    for n in arg.get("nodes", {}).values():
        layer = n["eat_profile"].split(",")[0].split(":")[1]
        out[layer] = json.loads(n["eat_meas"])
    return out


def print_collection(resp):
    print(f"   AM collection: {resp.get('status', resp.get('error'))}")
    for r in resp.get("rots", []):
        mark = "✓" if r["verified"] else "✗"
        print(f"     {mark} {r['rot']:5s} {'evidence verified' if r['verified'] else r['error']}")
        for c in r.get("checks", []):
            print(f"         · {c}")
    for n in resp.get("nodes", []):
        m = n.get("privacy_manifest") or {}
        print(f"     node {n['layer']:<11} ({n['source']}) {n['status']}"
              f"  suppressed={m.get('redacted_fields', [])}"
              f"  abstracted={[a[0] for a in m.get('aggregated_fields', [])]}")


def print_verification(result):
    res = (result or {}).get("result")
    if not res:
        print(f"   ✗ No verification result: {result}")
        return False
    trusted = res.get("trusted", False)
    print(f"\n   Trust Decision: {'TRUSTED ✅' if trusted else 'NOT TRUSTED ❌'}")
    print(f"   Explanation: {res.get('explanation', 'N/A')}")
    print("   Checks:")
    for d in res.get("details", []):
        mark = "✓" if d.get("verified") else "✗"
        err = f"  ({d.get('error')})" if d.get("error") else ""
        print(f"     {mark} {d.get('component')}{err}")
    return trusted
