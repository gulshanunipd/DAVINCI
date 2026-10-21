# Installing the Roots of Trust

This folder builds the **attested platform**: an emulated Arm v8 machine with
two real Roots of Trust (RoTs) and their MRAL collectors. Everything is
installed by one Docker build, from pinned upstream sources.

| RoT | What gets installed | Collector |
|-----|---------------------|-----------|
| **TPM 2.0** | `swtpm` + `swtpm-tools` (software TPM, EK certificate from the swtpm local CA), `tpm2-tools` | `tpm-adapter/tpm_adapter.py` → port **4010** |
| **OP-TEE (Arm TrustZone)** | Trusted Firmware-A v2.10, OP-TEE OS 4.1 with the attestation PTA, U-Boot v2025.01, Linux 6.6 (built in), run on `qemu-system-aarch64 -machine virt,secure=on` | `optee-adapter/` (workload TA + `davinci-attest` client in the guest) → port **4020** |
| Harness | measured boot into the TPM, power cycle, boot profiles | `platform/controller.py` → port **4000** |

## 1. Prerequisites

You need Docker with BuildKit, about 10 GB of free disk space and at least
4 GB of RAM for Docker.

* **macOS (Apple Silicon or Intel):** install and start Docker Desktop.
  ```bash
  brew install --cask docker && open -a Docker
  ```
* **Ubuntu/Debian (x86-64):** install Docker, plus arm64 emulation. One small
  build stage produces the arm64 guest userland, and Docker runs it through
  QEMU user mode.
  ```bash
  sudo apt install -y docker.io docker-buildx docker-compose-v2 qemu-user-static binfmt-support
  sudo usermod -aG docker "$USER"     # log out and back in
  ```
* **Ubuntu/Debian (arm64):** `sudo apt install -y docker.io docker-buildx docker-compose-v2`.

Alternatively, `vagrant up` at the repository root provisions an Ubuntu VM with
all of the above (`provisioning/playbook.yml`).

## 2. Build and start the platform

From the repository root:

```bash
make platform          # = docker build -t davinci-platform mral-adapters + docker run
```

The first build compiles the firmware, OP-TEE and the kernel, so it takes
20 to 40 minutes. Later builds are cached.

`make platform` starts the container with:

* ports 4000, 4010 and 4020 published;
* the named volume `davinci-platform-state`, which keeps the TPM state
  (EK/AK) and OP-TEE secure storage (the attestation key) across restarts;
* `keys/rot/` mounted at `/trust`. On first start the platform writes the TPM
  manufacturer CA there (`tpm-manufacturer-root.pem`,
  `tpm-manufacturer-issuer.pem`). This is the trust anchor the Attestation
  Manager uses for EK certificates.

To do the same without make:

```bash
DOCKER_BUILDKIT=1 docker build -t davinci-platform mral-adapters
docker run -d --name davinci-platform -p 4000:4000 -p 4010:4010 -p 4020:4020 \
  -v davinci-platform-state:/var/lib/davinci -v "$PWD/keys/rot":/trust davinci-platform
```

### Everything in Docker

To run the platform **and** the PCE (with PostgreSQL), the Attestation Manager
and the Verifier as containers, use Docker Compose instead:

```bash
make docker-run        # docker compose up -d --build (platform, pce-db, pce, AM, verifier)
make provision && make demo-compare
make docker-stop       # docker compose down
```

## 3. Check that both RoTs are up

```bash
curl -s localhost:4000/status
# {"profile": "good", "booted": true, "guest_ready": true, "error": null}

curl -s localhost:4010/enroll | head -c 200                       # TPM: EK cert + AK
curl -s "localhost:4010/quote?nonce=00112233&pcrs=0,1,2,3,4,5,6,7,8,9" | head -c 200
curl -s "localhost:4020/cgi-bin/attest?op=pubkey" | head -c 200   # OP-TEE PTA key
curl -s "localhost:4020/cgi-bin/attest?op=attest&nonce=00112233" | head -c 200
```

## 4. Enroll the RoTs and record reference values

With the PCE, Attestation Manager and Verifier running (`make run-pce`,
`make run-attestation-manager`, `make run-verifier`):

```bash
make provision
```

This performs the following steps:

1. **TPM enrollment.** The EK certificate must chain to the manufacturer CA.
   The AK must be a restricted, TPM-resident ECDSA-P256 key.
   `TPM2_MakeCredential`/`ActivateCredential` proves the AK is in that TPM.
2. **OP-TEE enrollment.** The PTA attestation key (RSA-3072, RSASSA-PSS) is
   registered.
3. **Reference values.** Writes `reference/reference-values.json`:
   * TPM PCRs computed from the platform images;
   * OP-TEE hashes from the known-good platform.

The enrolled keys are stored in `keys/enrollment.json`. Then run
`make demo-compare`.

## Recreating the RoTs

Removing the volume gives the platform a new TPM (new EK/AK, new CA) and a new
OP-TEE attestation key. Re-run `make provision` afterwards.

```bash
make platform-stop && docker volume rm davinci-platform-state && make platform
```

## Troubleshooting

* Logs are in the container under `/var/lib/davinci/`: `guest-console.log`
  (Linux), `secure-console.log` (OP-TEE), `qemu.log`, `swtpm.log`.
  Read them with `docker exec davinci-platform cat /var/lib/davinci/guest-console.log`.
* If `exec format error` appears during the build on x86-64, arm64 emulation
  is missing. Install `qemu-user-static binfmt-support`, or run
  `docker run --privileged --rm tonistiigi/binfmt --install arm64`.
* If enrollment reports `TPM manufacturer root CA not provisioned`, check that
  `keys/rot/` was mounted and that the platform has finished its first start.

## Layout

```
Dockerfile                 firmware (cross-compiled) | guest userland (arm64) | runtime
platform/start-platform.sh TPM manufacturing, swtpm, collectors, controller
platform/controller.py     measured boot (PCR 0-9 + event log), QEMU launch, boot profiles
platform/build-initramfs.sh normal-world initramfs (reproducible; "tampered-kernel" variant)
tpm-adapter/tpm_adapter.py TPM collector: /enroll, /activate, /quote
optee-adapter/ta/          workload Trusted Application (proxies the attestation PTA)
optee-adapter/host/        davinci-attest normal-world client (libteec)
optee-adapter/guest/       guest init + CGI endpoint
```
