#!/usr/bin/env python3
"""
Shared helpers for DAVINCI demos.

Produces the normalized evidence envelope the Attestation Manager expects, with a
real ECDSA-P256 Root-of-Trust signature over (measurement | ts) so the MRAL Auth
check (D3 Eq. 5) is genuine. Signing is done via the `openssl` CLI to avoid a
Python cryptography dependency.
"""

import hashlib
import json
import os
import subprocess
import time
import urllib.request
import urllib.error


def _post_json(url: str, payload: dict):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return {"status": f"http_{e.code}"}
    except Exception as e:  # noqa: BLE001
        return {"status": f"error: {e}"}


def _get_json(url: str):
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except Exception:  # noqa: BLE001
        return None

KEYS_DIR = os.environ.get(
    "DAVINCI_KEYS_DIR",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "keys"),
)


def rot_sign(source: str, measurement: str, ts: int) -> str:
    """ECDSA-P256 sign 'measurement|ts' with the RoT private key -> hex(DER)."""
    priv = os.path.join(KEYS_DIR, f"rot_{source}_priv.pem")
    msg = f"{measurement}|{ts}".encode()
    p = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", priv],
        input=msg,
        capture_output=True,
    )
    if p.returncode != 0:
        raise RuntimeError(f"openssl sign failed for {source}: {p.stderr.decode()}")
    return p.stdout.hex()


def make_evidence(source: str, seed: str, claims: dict = None, tamper: bool = False) -> dict:
    """
    Build a signed evidence envelope. The RoT signs the *authentic* measurement.
    If `tamper` is set, the measurement is altered AFTER signing to simulate an
    adversary modifying evidence in transit — the RoT signature will then fail
    the MRAL Auth check and the evidence is rejected.
    """
    measurement = hashlib.sha256(seed.encode()).hexdigest()
    ts = int(time.time())
    sig = rot_sign(source, measurement, ts)
    if tamper:
        measurement = hashlib.sha256(("tampered_" + seed).encode()).hexdigest()
    return {
        "source": source,
        "measurement": measurement,
        "ts": ts,
        "claims": claims or {},
        "rot_sig": sig,
        # Sensitive, verification-irrelevant fields — suppressed by the PCE
        # (minimal disclosure, D3 §10 / D2 Property 11.3).
        "hostname": "prod-node-07.internal",
        "ip_address": "10.0.3.7",
    }


class DavinciClient:
    def __init__(self, am_url=None, ver_url=None):
        self.am_url = am_url or os.environ.get("ATTESTATION_MANAGER_URL", "http://localhost:3030")
        self.ver_url = ver_url or os.environ.get("VERIFIER_URL", "http://localhost:3031")

    def send_boot(self, session_id, layer, source, evidence):
        return _post_json(
            f"{self.am_url}/attest/boot",
            {
                "session_id": session_id,
                "layer": layer,
                "source": source,
                "evidence": json.dumps(evidence),
            },
        )

    def send_runtime(self, session_id, evidence):
        return _post_json(
            f"{self.am_url}/attest/runtime",
            {"session_id": session_id, "evidence": json.dumps(evidence)},
        )

    def verify(self, session_id, nonce):
        return _post_json(
            f"{self.ver_url}/verify",
            {"session_id": session_id, "nonce": nonce},
        )


def print_verification(result):
    if not result:
        print("   ✗ No verification result")
        return False
    res = result.get("result", {})
    trusted = res.get("trusted", False)
    print(f"\n   Trust Decision: {'TRUSTED ✅' if trusted else 'NOT TRUSTED ❌'}")
    print(f"   Explanation: {res.get('explanation', 'N/A')}")
    print("   Checks:")
    for d in res.get("details", []):
        mark = "✓" if d.get("verified") else "✗"
        err = f"  ({d.get('error')})" if d.get("error") else ""
        print(f"     {mark} {d.get('component')}{err}")
    return trusted
