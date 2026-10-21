#!/usr/bin/env python3
"""
DAVINCI platform controller (test harness, not part of the attested path).

Power-cycles the emulated Arm platform and performs its measured boot:

  1. TPM reset      swtpm power cycle + TPM2_Startup(CLEAR): all PCRs back to 0.
  2. Measured boot  every boot component is hashed and extended into the TPM
                    *before* it runs, and recorded in a TCG-style event log.
                    This is the SRTM chain that BL1/BL2 (TF-A MEASURED_BOOT) or
                    UEFI perform on hardware; here the launcher plays that role
                    for the exact images handed to QEMU.
  3. Boot           QEMU virt (secure=on): TF-A -> OP-TEE OS -> U-Boot -> Linux.

Profiles select which images boot:
  good             reference images
  tampered-kernel  initramfs with an implant        -> PCR 9 changes
  tampered-ta      rogue (backdoored) workload TA   -> OP-TEE TA hash changes

HTTP API (port 4000):
  GET  /status      current profile and guest state
  POST /boot        {"profile": "..."}  power-cycle into a profile
  GET  /reference   expected PCR values of the *good* profile, computed from
                    the images alone (vendor reference integrity manifest)
"""

import hashlib
import json
import os
import shutil
import subprocess
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FW = "/opt/davinci/fw"
TA_SRC = "/opt/davinci/ta"
STATE = "/var/lib/davinci"
EVENT_LOG = os.path.join(STATE, "eventlog.json")
SERIAL_LOG = os.path.join(STATE, "guest-console.log")
SECURE_LOG = os.path.join(STATE, "secure-console.log")
TCTI = os.environ.get("TPM2TOOLS_TCTI", "swtpm:host=127.0.0.1,port=2321")
PROFILES = ("good", "tampered-kernel", "tampered-ta")
PCRS = list(range(10))

MACHINE = ("virt,acpi=off,secure=on,mte=off,gic-version=3,virtualization=false;"
           "cpu=max,sme=off,pauth-impdef=on;smp=2;m=1057")
CMDLINE = "console=ttyAMA0 rdinit=/init"

_lock = threading.Lock()
_state = {"profile": None, "booted": False, "guest_ready": False, "error": None}
_qemu = None


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def boot_events(profile):
    """The ordered measurements of a boot, as (pcr, type, description, digest)."""
    initramfs = "initramfs-tampered-kernel.cpio.gz" if profile == "tampered-kernel" \
        else "initramfs-good.cpio.gz"
    f = lambda name: _sha256_file(os.path.join(FW, name))  # noqa: E731
    s = lambda text: hashlib.sha256(text.encode()).hexdigest()  # noqa: E731
    return [
        (0, "EV_S_CRTM_CONTENTS", "BL1: TF-A boot ROM (CRTM)", f("bl1.bin")),
        (0, "EV_POST_CODE", "BL2: TF-A trusted boot firmware", f("bl2.bin")),
        (0, "EV_POST_CODE", "BL31: TF-A EL3 runtime firmware", f("bl31.bin")),
        (1, "EV_PLATFORM_CONFIG_FLAGS", "Platform configuration: " + MACHINE, s(MACHINE)),
        (2, "EV_EFI_PLATFORM_FIRMWARE_BLOB", "BL32: OP-TEE OS header", f("bl32.bin")),
        (2, "EV_EFI_PLATFORM_FIRMWARE_BLOB", "BL32: OP-TEE OS pager", f("bl32_extra1.bin")),
        (2, "EV_EFI_PLATFORM_FIRMWARE_BLOB", "BL32: OP-TEE OS pageable", f("bl32_extra2.bin")),
        (4, "EV_EFI_BOOT_SERVICES_APPLICATION", "BL33: U-Boot", f("bl33.bin")),
        (8, "EV_IPL", "Kernel command line: " + CMDLINE, s(CMDLINE)),
        (9, "EV_IPL", "Linux kernel Image", f("Image")),
        (9, "EV_IPL", "initramfs " + initramfs, f(initramfs)),
    ]


def replay(events):
    """PCR values that a sequence of SHA-256 extends produces from reset."""
    pcrs = {i: bytes(32) for i in PCRS}
    for pcr, _t, _d, digest in events:
        pcrs[pcr] = hashlib.sha256(pcrs[pcr] + bytes.fromhex(digest)).digest()
    return {str(i): v.hex() for i, v in pcrs.items()}


def _tpm(*args):
    env = dict(os.environ, TPM2TOOLS_TCTI=TCTI)
    subprocess.run(list(args), check=True, env=env, capture_output=True)


def _stop_qemu():
    global _qemu
    if _qemu and _qemu.poll() is None:
        _qemu.terminate()
        try:
            _qemu.wait(timeout=10)
        except subprocess.TimeoutExpired:
            _qemu.kill()
    _qemu = None


def _start_qemu(initramfs):
    global _qemu
    for log in (SERIAL_LOG, SECURE_LOG):
        open(log, "w").close()
    cmd = [
        "qemu-system-aarch64", "-nographic", "-smp", "2",
        "-cpu", "max,sme=off,pauth-impdef=on",
        "-machine", "virt,acpi=off,secure=on,mte=off,gic-version=3,virtualization=false",
        "-m", "1057", "-semihosting-config", "enable=on,target=native",
        "-bios", "bl1.bin",
        "-kernel", "Image", "-initrd", initramfs, "-append", CMDLINE,
        "-netdev", "user,id=n0,hostfwd=tcp::4020-:8080",
        "-device", "virtio-net-device,netdev=n0",
        "-fsdev", f"local,id=fs0,path={STATE}/tee,security_model=none",
        "-device", "virtio-9p-device,fsdev=fs0,mount_tag=teestore",
        "-fsdev", f"local,id=fs1,path={STATE}/ta,security_model=none,readonly=on",
        "-device", "virtio-9p-device,fsdev=fs1,mount_tag=tastore",
        "-serial", f"file:{SERIAL_LOG}", "-serial", f"file:{SECURE_LOG}",
        "-monitor", "none", "-display", "none",
    ]
    # BL2 loads BL31/BL32/BL33 from the working directory via semihosting.
    _qemu = subprocess.Popen(cmd, cwd=FW, stdout=subprocess.DEVNULL,
                             stderr=open(os.path.join(STATE, "qemu.log"), "w"))


def _wait_guest(timeout=180):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _qemu is None or _qemu.poll() is not None:
            raise RuntimeError("QEMU exited during boot (see qemu.log)")
        try:
            with urllib.request.urlopen(
                    "http://127.0.0.1:4020/cgi-bin/attest?op=pubkey", timeout=5) as r:
                if b'"rot":"optee"' in r.read():
                    return
        except Exception:  # noqa: BLE001 - guest not up yet
            pass
        time.sleep(1)
    raise RuntimeError("guest did not become ready")


def power_cycle(profile):
    if profile not in PROFILES:
        raise ValueError(f"unknown profile {profile!r}; expected one of {PROFILES}")
    with _lock:
        _state.update(profile=profile, booted=False, guest_ready=False, error=None)
        _stop_qemu()

        # 1. Platform reset: orderly TPM2_Shutdown, power cycle, TPM2_Startup.
        #    PCRs return to their reset value. Skipping the shutdown would be a
        #    non-orderly reset, which the TPM counts toward DA lockout.
        subprocess.run(["tpm2_shutdown", "-c"], env=dict(os.environ, TPM2TOOLS_TCTI=TCTI),
                       capture_output=True)
        subprocess.run(["swtpm_ioctl", "--tcp", "127.0.0.1:2322", "-i"],
                       check=True, capture_output=True)
        _tpm("tpm2_startup", "-c")

        # 2. Measured boot: extend each measurement before the component runs.
        events = boot_events(profile)
        log = []
        for pcr, etype, desc, digest in events:
            _tpm("tpm2_pcrextend", f"{pcr}:sha256={digest}")
            log.append({"pcr": pcr, "type": etype, "description": desc,
                        "digest": {"sha256": digest}})
        with open(EVENT_LOG, "w") as f:
            json.dump(log, f, indent=1)

        # Trusted Applications offered to OP-TEE for this profile.
        ta_dir = os.path.join(STATE, "ta")
        shutil.rmtree(ta_dir, ignore_errors=True)
        os.makedirs(ta_dir)
        variant = "tampered" if profile == "tampered-ta" else "good"
        for name in os.listdir(os.path.join(TA_SRC, variant)):
            shutil.copy(os.path.join(TA_SRC, variant, name), ta_dir)

        # 3. Boot the emulated platform.
        initramfs = "initramfs-tampered-kernel.cpio.gz" if profile == "tampered-kernel" \
            else "initramfs-good.cpio.gz"
        _start_qemu(initramfs)
        _state["booted"] = True
        try:
            _wait_guest()
            _state["guest_ready"] = True
        except RuntimeError as e:
            _state["error"] = str(e)
            raise


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if self.path == "/status":
            self._send(200, _state)
        elif self.path == "/reference":
            self._send(200, {"bank": "sha256", "pcrs": replay(boot_events("good")),
                             "source": "computed from platform images (good profile)"})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        if self.path != "/boot":
            return self._send(404, {"error": "not found"})
        length = int(self.headers.get("Content-Length", 0))
        try:
            req = json.loads(self.rfile.read(length) or b"{}")
            power_cycle(req.get("profile", "good"))
            self._send(200, _state)
        except (ValueError, RuntimeError, subprocess.CalledProcessError) as e:
            self._send(500, {"error": str(e), **_state})

    def log_message(self, fmt, *args):
        print("controller:", fmt % args, flush=True)


def _first_boot(profile):
    # A container stop is a non-orderly TPM power loss. As the platform owner,
    # reset the dictionary-attack counter once at power-on (empty lockout auth).
    try:
        subprocess.run(["swtpm_ioctl", "--tcp", "127.0.0.1:2322", "-i"],
                       check=True, capture_output=True)
        _tpm("tpm2_startup", "-c")
        _tpm("tpm2_dictionarylockout", "--clear-lockout")
    except subprocess.CalledProcessError as e:
        print(f"controller: DA reset skipped: {e.stderr.decode()[-200:]}", flush=True)
    power_cycle(profile)


def main():
    profile = os.environ.get("DAVINCI_PROFILE", "good")
    threading.Thread(target=_first_boot, args=(profile,), daemon=True).start()
    print(f"controller: booting profile '{profile}', API on :4000", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 4000), Handler).serve_forever()


if __name__ == "__main__":
    main()
