# DAVINCI Prototype

A prototype implementation of the **DAVINCI** deep-attestation framework
(*Deep Attestation framework for VIrtualized Network Communication Integrity*),
aligned with deliverables **D2** (theoretical specification) and **D3** (design &
analysis). It verifies the integrity of a layered stack
(Platform → Hypervisor → Guest → Application) across **two real, heterogeneous
Roots of Trust**, applies privacy transformations, and produces a
**cryptographically justified** trust decision.

## Roots of Trust

| RoT | Implementation | Layers it attests | Evidence |
|-----|----------------|-------------------|----------|
| **TPM 2.0** | [swtpm](https://github.com/stefanberger/swtpm) software TPM, EK certified by the swtpm local CA (the "TPM manufacturer") | Platform (PCR 0–7: TF-A BL1/BL2/BL31, OP-TEE image, U-Boot), Hypervisor (PCR 8–9: kernel cmdline, kernel, initramfs) | `TPM2_Quote` signed by a restricted ECDSA-P256 AK + measured-boot event log |
| **OP-TEE (Arm TrustZone)** | TF-A v2.10 + OP-TEE OS 4.1 on QEMU `virt,secure=on`, attestation PTA enabled | Guest (TEE OS runtime memory), Application (workload TA runtime memory + signed header) | PTA measurements signed with the device RSA-3072 key (RSASSA-PSS) held in OP-TEE secure storage |

Both run on one emulated Arm v8 platform (`mral-adapters/`, a Docker image built
from pinned upstream sources): the platform boots
TF-A → OP-TEE → U-Boot → Linux, every boot component is measured into the TPM
before it runs, and the normal-world Linux runs the OP-TEE collector next to the
workload Trusted Application.

## What this prototype implements (D2/D3 mapping)

The five abstract algorithms of the scheme `Π_DAV = (Setup, Collect, Attest,
Transform, Verify)` are instantiated concretely:

| Algorithm | Component | Implementation |
|-----------|-----------|----------------|
| **Setup** | AM + MRAL | ECDSA-P256 AM key pair (`pk_AM` = Verifier trust anchor τ). RoT **enrollment** (`POST /mral/enroll`): EK certificate → manufacturer CA, AK must be a restricted TPM-resident signing key, `TPM2_MakeCredential`/`ActivateCredential` binds AK to EK; OP-TEE PTA key registered |
| **Collect** | MRAL | The AM calls each RoT's collector with qualifying data `H(sid ‖ c)` and verifies **natively in Rust**: quote signature, nonce, PCR digest, event-log replay (TPM); three RSASSA-PSS signatures + nonce (OP-TEE). Unverifiable evidence is not admitted (`Auth = 0`) |
| **Transform** | PCE | Disclosure policy `{disclose, abstract, suppress}` + session-scoped pseudonyms (AK name, OP-TEE key fingerprint); applied **fail-closed** |
| **Attest** | AMC + ARG | SHA-256 hash-linked AMC chain; ARG trust edges are **AM-signed (ECDSA)**; challenge-bound signed output export |
| **Verify** | Verifier | `ECDSA.verify(pk_AM,out,pf) ∧ out.c==c ∧ ϕ_G(G') ∧ appraise(G')` — single-use verifier challenges, graph validity, RoT-level freshness, reference values |

`ϕ_G` checks: platform-root present, every edge signature valid under `pk_AM`,
layer monotonicity, acyclicity, `Π_bind` admissibility, and cross-layer trust
continuity. `appraise` checks that every layer is attested by its RoT, that the
nonce inside **every RoT signature** derives from this verifier's challenge, and
that every PCR / TEE hash equals its reference value.

### Security-property coverage

| D2 property | How it is enforced here |
|-------------|-------------------------|
| Deep Integrity (§7) | Any modified boot component changes a TPM PCR; a modified TA changes the OP-TEE hash → reference-value appraisal fails |
| Cross-Layer Trust Continuity (§8) | Reachability check to the Platform root over AM-signed edges |
| Authenticity (§9) | Quote signed by an EK-bound AK; OP-TEE evidence signed by the enrolled PTA key; AM signature over output + edges |
| Freshness / Replay (§10) | `H(sid ‖ c)` inside each RoT signature; verifier challenges are single-use and expire |
| Privacy (§11) | PCE pseudonymizes stable RoT identifiers, abstracts event logs/quotes/signatures, suppresses host identifiers |
| Multi-modal Soundness (§12) | Each RoT verified independently against its own trust material; forging one modality is caught |

## Components

- `mral-adapters/` — the attested platform image: swtpm, TF-A/OP-TEE/U-Boot/Linux on QEMU, and the MRAL **collectors** (`tpm-adapter/` :4010, `optee-adapter/` TA + client :4020) plus a boot-profile **controller** (:4000, test harness). **Installing the RoTs:** see [mral-adapters/README.md](mral-adapters/README.md).
- `attestation-manager/` — Attester (Rust, warp). `src/mral/` is the MRAL: collector client + native TPM/OP-TEE verification. Port **3030**.
- `verifier/` — Verifier (Rust, warp). Port **3031**.
- `pce-service/` — Privacy Control Engine (Rust, warp; optional Postgres). Port **3032**.
- `keys/` — AM key (`gen-keys.sh`); `keys/rot/` receives the TPM manufacturer CA; `keys/enrollment.json` the enrolled RoT keys.
- `reference/` — reference values written by `demo/provision.py`.
- `demo/` — provisioning, end-to-end and trusted-vs-untrusted demos.

## Getting started

Prerequisites: Docker, Rust (rustup), OpenSSL + pkg-config, Python 3.

```bash
export PKG_CONFIG_PATH="$(brew --prefix openssl@3)/lib/pkgconfig"   # macOS
make build            # AM key + the three Rust services
make platform         # build (~20 min first time) and start the attested platform
                      # (RoT installation details: mral-adapters/README.md)
```

Run the three services, each in its own terminal (**PCE first**):

```bash
make run-pce                  # :3032
make run-attestation-manager  # :3030
make run-verifier             # :3031
```

Provision once, then drive the demos:

```bash
make provision        # enroll TPM + OP-TEE, record reference values
make demo             # one attestation round, every stage shown
make demo-compare     # all scenarios side by side (also the e2e test)
```

Alternatively `make docker-run` starts the platform and all services with
Docker Compose; then run `make provision` and the demos from the host.

### Scenarios

| Scenario | What changes | Expected decision | Failing check |
|----------|--------------|-------------------|---------------|
| `good` | nothing | **TRUSTED** | — |
| `tampered-kernel` | implant added to the measured initramfs | NOT TRUSTED | Reference Values: Kernel/initramfs (PCR 9) |
| `tampered-ta` | backdoored workload TA (validly signed, same UUID) | NOT TRUSTED | Reference Values: workload TA (OP-TEE) |
| `replay` | already-used verifier challenge | NOT TRUSTED | Challenge Issued by Verifier |

Run one with `make demo-trust SCENARIO=tampered-ta`. Forged quotes, PCR values,
event logs, nonces and keys are covered by the MRAL unit tests (`make test`),
which run on real evidence captured from the platform.

### Configuration (env vars)

| Variable | Default | Used by |
|----------|---------|---------|
| `DAVINCI_KEYS_DIR` | `../keys` | AM, Verifier |
| `DAVINCI_TRUST_DIR` | `$DAVINCI_KEYS_DIR/rot` | AM (TPM manufacturer CA) |
| `MRAL_TPM_URL` | `http://localhost:4010` | AM |
| `MRAL_OPTEE_URL` | `http://localhost:4020/cgi-bin/attest` | AM |
| `PCE_URL` | `http://localhost:3032` | AM |
| `ATTESTATION_MANAGER_URL` | `http://localhost:3030` | Verifier, demos |
| `DAVINCI_REFERENCE` | `../reference/reference-values.json` | Verifier, provisioning |
| `DATABASE_URL` | *(unset → in-memory)* | PCE persistence |
| `AM_BIND` / `VERIFIER_BIND` | `0.0.0.0:<port>` | bind address |

## APIs

**Attestation Manager**
- `POST /mral/enroll` — enroll the RoTs (EK chain, AK profile, credential activation; OP-TEE key)
- `GET  /mral/status` — enrolled RoT keys
- `POST /attest/collect` — `{session_id, nonce}`: MRAL collects + verifies, PCE transforms, ARG built
- `GET  /attest/output/{sid}?nonce=<c>` — signed, challenge-bound output `{out, pf}`
- `GET  /arg/{sid}` — raw ARG (debug); `GET /pubkey` — trust anchor τ

**Verifier**
- `GET  /challenge` — fresh single-use challenge (5 min)
- `POST /verify` — `{session_id, nonce}` → trust decision with per-check details

**PCE**
- `POST /privacy/transform`, `POST /validate/node`, `POST /resolve/pseudonym`, `GET /health`

**Platform** (collectors and harness, on the attested platform)
- TPM collector `:4010`: `GET /enroll`, `POST /activate`, `GET /quote?nonce=&pcrs=`
- OP-TEE collector `:4020`: `GET /cgi-bin/attest?op=pubkey`, `?op=attest&nonce=`
- Controller `:4000`: `GET /status`, `POST /boot {profile}`, `GET /reference`

## Prototype boundary

- Both RoTs are **software implementations** of real RoT technologies: swtpm is a
  complete TPM 2.0, and OP-TEE runs in a real TrustZone secure world, but on QEMU,
  not on silicon. Their keys therefore are not hardware-protected; the protocols,
  data structures and verification are the ones used with hardware.
- Measured boot is performed by the platform launcher (it extends each image into
  the TPM before QEMU runs it), standing in for TF-A `MEASURED_BOOT` on hardware.
- The OP-TEE attestation key is trusted on first use at provisioning; on a product
  it would be certified at manufacturing. OP-TEE uses its test hardware-unique key.
- AM bootstrap attestation (D3 §8.2) is not implemented.
