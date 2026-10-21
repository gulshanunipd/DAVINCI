#!/usr/bin/env python3
"""
MRAL TPM 2.0 collector (runs on the attested platform).

Talks to the platform TPM (swtpm, via tpm2-tools) and returns raw TPM
structures. It holds no keys and makes no trust decisions: the Attestation
Manager's MRAL verifies everything (EK certificate chain, credential
activation, quote signature, nonce, PCR digest, event-log replay).

Keys (created once, persisted in TPM NV):
  EK  0x81010001  RSA-2048 endorsement key, certified by the TPM manufacturer
                  CA (EK certificate in NV index 0x01c00002)
  AK  0x81010002  restricted ECDSA-P256/SHA-256 attestation key under the EK

HTTP API (port 4010):
  GET  /enroll                     EK certificate, AK public area and name
  POST /activate                   {"id_object","encrypted_secret"} -> {"secret"}
                                   (TPM2_ActivateCredential: proves the AK lives
                                   in the TPM that owns the certified EK)
  GET  /quote?nonce=<hex>&pcrs=0,1 TPM2_Quote over SHA-256 PCRs + PCR values +
                                   measured-boot event log
"""

import base64
import json
import os
import socket
import struct
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

TCTI = os.environ.get("TPM2TOOLS_TCTI", "swtpm:host=127.0.0.1,port=2321")
EVENT_LOG = os.environ.get("DAVINCI_EVENT_LOG", "/var/lib/davinci/eventlog.json")
EK_HANDLE = "0x81010001"
AK_HANDLE = "0x81010002"
EK_CERT_NV = "0x01c00002"
CREDENTIAL_MAGIC = 0xBADCC0DE

_tpm_lock = threading.Lock()


def tpm(*args, check=True):
    env = dict(os.environ, TPM2TOOLS_TCTI=TCTI)
    return subprocess.run(list(args), env=env, capture_output=True, check=check)


def _flush():
    tpm("tpm2_flushcontext", "-t", check=False)
    tpm("tpm2_flushcontext", "-s", check=False)


def ensure_keys(work):
    """Create and persist the EK/AK on first use."""
    handles = tpm("tpm2_getcap", "handles-persistent").stdout.decode()
    if EK_HANDLE not in handles:
        tpm("tpm2_createek", "-c", EK_HANDLE, "-G", "rsa")
    if AK_HANDLE not in handles:
        ctx = os.path.join(work, "ak.ctx")
        tpm("tpm2_createak", "-C", EK_HANDLE, "-c", ctx, "-G", "ecc", "-g", "sha256",
            "-s", "ecdsa", "-u", os.path.join(work, "ak.tmp.pub"),
            "-n", os.path.join(work, "ak.tmp.name"))
        tpm("tpm2_evictcontrol", "-C", "o", "-c", ctx, AK_HANDLE)
    _flush()


def _trim_der(buf):
    """The EK certificate NV index may be padded; keep just the DER SEQUENCE."""
    if buf[1] < 0x80:
        return buf[:2 + buf[1]]
    n = buf[1] & 0x7F
    return buf[:2 + n + int.from_bytes(buf[2:2 + n], "big")]


def enroll():
    with _tpm_lock, tempfile.TemporaryDirectory() as work:
        ensure_keys(work)
        ek_der = os.path.join(work, "ek.der")
        tpm("tpm2_nvread", EK_CERT_NV, "-o", ek_der)
        der = _trim_der(open(ek_der, "rb").read())
        b64 = base64.b64encode(der).decode()
        pem = ("-----BEGIN CERTIFICATE-----\n"
               + "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
               + "\n-----END CERTIFICATE-----\n")
        pub, name = os.path.join(work, "ak.pub"), os.path.join(work, "ak.name")
        tpm("tpm2_readpublic", "-c", AK_HANDLE, "-o", pub, "-n", name)
        _flush()
        return {
            "rot": "tpm",
            "ek_cert": pem,
            "ek_handle": EK_HANDLE,
            "ak_handle": AK_HANDLE,
            "ak_public": open(pub, "rb").read().hex(),   # TPM2B_PUBLIC
            "ak_name": open(name, "rb").read().hex(),    # nameAlg || H(TPMT_PUBLIC)
        }


def activate(id_object_hex, encrypted_secret_hex):
    id_object = bytes.fromhex(id_object_hex)
    secret = bytes.fromhex(encrypted_secret_hex)
    blob = (struct.pack(">II", CREDENTIAL_MAGIC, 1)
            + struct.pack(">H", len(id_object)) + id_object
            + struct.pack(">H", len(secret)) + secret)
    with _tpm_lock, tempfile.TemporaryDirectory() as work:
        cred, out, sess = (os.path.join(work, n) for n in ("cred.in", "cred.out", "s.ctx"))
        open(cred, "wb").write(blob)
        try:
            # The EK's authPolicy is PolicySecret(TPM_RH_ENDORSEMENT).
            tpm("tpm2_startauthsession", "--policy-session", "-S", sess)
            tpm("tpm2_policysecret", "-S", sess, "-c", "e")
            tpm("tpm2_activatecredential", "-c", AK_HANDLE, "-C", EK_HANDLE,
                "-i", cred, "-o", out, "-P", f"session:{sess}")
            return {"secret": open(out, "rb").read().hex()}
        finally:
            tpm("tpm2_flushcontext", sess, check=False)
            _flush()


def quote(nonce_hex, pcrs):
    sel = "sha256:" + ",".join(str(p) for p in pcrs)
    with _tpm_lock, tempfile.TemporaryDirectory() as work:
        msg, sig, vals = (os.path.join(work, n) for n in ("q.msg", "q.sig", "pcrs.bin"))
        try:
            tpm("tpm2_quote", "-c", AK_HANDLE, "-l", sel, "-q", nonce_hex,
                "-m", msg, "-s", sig, "-g", "sha256")
            tpm("tpm2_pcrread", sel, "-o", vals)
        finally:
            _flush()
        attest, signature = open(msg, "rb").read(), open(sig, "rb").read()
        raw = open(vals, "rb").read()
    try:
        event_log = json.load(open(EVENT_LOG))
    except (OSError, ValueError):
        event_log = []
    return {
        "rot": "tpm",
        "nonce": nonce_hex,
        "attest": attest.hex(),        # TPMS_ATTEST
        "signature": signature.hex(),  # TPMT_SIGNATURE
        "pcr_bank": "sha256",
        "pcrs": {str(p): raw[32 * i:32 * (i + 1)].hex() for i, p in enumerate(pcrs)},
        "event_log": event_log,
        "hostname": socket.gethostname(),
    }


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _guard(self, fn):
        try:
            self._send(200, fn())
        except subprocess.CalledProcessError as e:
            self._send(500, {"error": f"{e.cmd[0]} failed", "stderr": e.stderr.decode()[-400:]})
        except (ValueError, KeyError, OSError) as e:
            self._send(400, {"error": str(e)})

    def do_GET(self):  # noqa: N802
        url = urlparse(self.path)
        q = parse_qs(url.query)
        if url.path == "/enroll":
            self._guard(enroll)
        elif url.path == "/quote":
            nonce = q.get("nonce", [""])[0]
            pcrs = [int(p) for p in q.get("pcrs", ["0,1,2,3,4,5,6,7,8,9"])[0].split(",")]
            if not nonce or len(nonce) > 128:
                return self._send(400, {"error": "nonce (hex, <=64 bytes) required"})
            self._guard(lambda: quote(nonce, pcrs))
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        if self.path != "/activate":
            return self._send(404, {"error": "not found"})
        req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        self._guard(lambda: activate(req["id_object"], req["encrypted_secret"]))

    def log_message(self, fmt, *args):
        print("tpm-adapter:", fmt % args, flush=True)


if __name__ == "__main__":
    print("tpm-adapter: MRAL TPM collector on :4010", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 4010), Handler).serve_forever()
