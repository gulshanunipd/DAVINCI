# DAVINCI Prototype

A prototype implementation of the **DAVINCI** deep-attestation framework
(*Deep Attestation framework for VIrtualized Network Communication Integrity*),
aligned with deliverables **D2** (theoretical specification) and **D3** (design &
analysis). It verifies the integrity of a layered virtualized stack
(Platform → Hypervisor → Guest → Application) across heterogeneous Roots of
Trust, applies privacy transformations, and produces a **cryptographically
justified** trust decision.

## What this prototype implements (D2/D3 mapping)

The five abstract algorithms of the scheme `Π_DAV = (Setup, Collect, Attest,
Transform, Verify)` are instantiated concretely, using **ECDSA-P256 + SHA-256**
(the primitives D2 §14 / D3 §5 rely on):

| Algorithm | Component | Implementation |
|-----------|-----------|----------------|
| **Setup** | Attestation Manager | ECDSA-P256 AM key pair `sk_AM/pk_AM`; `pk_AM` is the Verifier trust anchor τ (`GET /pubkey`) |
| **Collect** | MRAL | Each source signs `(µ‖ts)` with its RoT key; the AM verifies this **`Auth`** signature before admitting evidence |
| **Transform** | PCE | Disclosure policy `{disclose, abstract=pseudonymize, suppress}` + session-scoped pseudonyms; applied **fail-closed** |
| **Attest** | AMC + ARG | SHA-256 hash-linked AMC chain; ARG trust edges are **AM-signed (ECDSA)**; challenge-bound signed output export |
| **Verify** | Verifier | `ECDSA.verify(pk_AM,out,pf) ∧ out.c==c ∧ ϕ_G(G')` — real signature + freshness + graph validity |

The Verifier's `ϕ_G` checks: platform-root present, **every edge signature valid
under `pk_AM`**, layer monotonicity, acyclicity, `Π_bind` admissibility, and
cross-layer trust continuity (every node has a signed trust path to the
Platform root).

### Security-property coverage

| D2 property | How it is enforced here |
|-------------|-------------------------|
| Deep Integrity (§7) | Tampered evidence fails `Auth`; unsigned/forged nodes fail `ϕ_G` |
| Cross-Layer Trust Continuity (§8) | Reachability check to the Platform root over signed edges |
| Authenticity (§9) | ECDSA signature over the exported output + per-edge signatures |
| Freshness / Replay (§10) | Verifier challenge bound into the signed output; checked on verify |
| Privacy (§11) | PCE pseudonymization + field suppression (minimal disclosure) |
| Multi-modal Soundness (§12) | Per-source RoT `Auth`; forging one modality's evidence is caught |

**Prototype boundary:** hardware RoTs are *simulated* — the Python sources sign
evidence with per-source ECDSA test keys (`keys/rot_*_priv.pem`) that stand in
for hardware-protected `sk_r`. AM **bootstrap attestation** (D3 §8.2) is not
implemented and is left as documented future work.

## Components

- `attestation-manager/` — Attester (Rust, warp) — Collect/Auth, Attest, signed ARG export. Port **3030**.
- `verifier/` — Verifier (Rust, warp) — the concrete `Verify` predicate. Port **3031**.
- `pce-service/` — Privacy Control Engine (Rust, warp; optional Postgres). Port **3032**.
- `mral-adapters/` — Python evidence sources (TPM / CC) for standalone testing.
- `keys/` — ECDSA-P256 key material (generate with `keys/gen-keys.sh`).
- `demo/` — end-to-end and trusted-vs-untrusted demos.
- `docs/` — D2/D3 reports and component notes.

## Getting started

```bash
# 1. Prerequisites: Rust (rustup), and OpenSSL + pkg-config
#    macOS: brew install openssl@3 pkg-config
export PKG_CONFIG_PATH="$(brew --prefix openssl@3)/lib/pkgconfig"

# 2. Generate keys and build
make build          # runs keys/gen-keys.sh, then builds all three services
```

Run the three services (each in its own terminal — **start the PCE first**):

```bash
make run-pce                  # :3032  (run from pce-service/ so it finds policies/)
make run-attestation-manager  # :3030
make run-verifier             # :3031
```

Then drive the demos:

```bash
make demo-compare     # trusted vs untrusted, side by side
make demo             # full end-to-end scenario
```

Expected: the trusted run is **TRUSTED** (all checks pass); the untrusted run
(guest evidence tampered after signing) is **NOT TRUSTED**, failing on
Cross-Layer Trust Continuity because the tampered guest evidence is rejected at
`Auth` and never enters the graph.

### Configuration (env vars)

| Variable | Default | Used by |
|----------|---------|---------|
| `DAVINCI_KEYS_DIR` | `../keys` | AM, Verifier (key material) |
| `PCE_URL` | `http://localhost:3032` | AM |
| `ATTESTATION_MANAGER_URL` | `http://localhost:3030` | Verifier |
| `DATABASE_URL` | *(unset → in-memory)* | PCE persistence |
| `AM_BIND` / `VERIFIER_BIND` / `PCE_BIND` | `0.0.0.0:<port>` | bind address |

`docker-compose.yml` wires these across containers (keys mounted at `/keys`).

## APIs

**Attestation Manager**
- `POST /attest/boot` — submit boot evidence `{session_id, layer, source, evidence}`
- `POST /attest/runtime` — submit runtime (IMA) evidence `{session_id, evidence}`
- `GET  /attest/output/{sid}?nonce=<c>` — signed, challenge-bound output `{out, pf}`
- `GET  /arg/{sid}` — raw ARG (debug); `GET /pubkey` — trust anchor τ

**Verifier**
- `POST /verify` — `{session_id, nonce}` → full trust decision with per-check details

**PCE**
- `POST /privacy/transform`, `POST /validate/node`, `POST /resolve/pseudonym`, `GET /health`

## Known limitations

1. Hardware RoTs are simulated with software ECDSA test keys (no real TPM / SEV-SNP / TDX / CCA hardware).
2. AM bootstrap attestation (D3 §8.2) is not implemented.
3. The Guest layer uses a single-parent chain; multi-RoT parallel branches at one layer are supported by the data model but not exercised by the demos.
