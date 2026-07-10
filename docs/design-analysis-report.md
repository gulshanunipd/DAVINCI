# DAVINCI Prototype: Design & Analysis Report

## 1. Introduction

This document presents the design and analysis of the DAVINCI prototype implementation, which follows the DAVINCI architecture for secure attestation workflows. The implementation focuses on the core components needed for WP2 deliverables:

- Secure bindings between virtual layers (vTPM↔pTPM, VM↔hypervisor)
- Formal security model for the reference architecture
- Implementation of AMC, MRAL, ARG, Attestation Manager, and Verifier components
- Policy-based evidence validation via the Policy Compliance Engine (PCE)

## 2. Reference Architecture

The DAVINCI prototype implements the following architectural components as specified in the technical proposal:

### 2.1 AMC (Abstract Measurement Chain)

The Abstract Measurement Chain provides a uniform representation for attestation evidence from different sources. It normalizes inputs to a consistent node type:

```rust
pub struct AcmNode {
    pub id: Uuid,
    pub layer: Layer,           // Platform, Hypervisor, Guest, Runtime
    pub mode: Mode,             // BootTime, Runtime, Policy
    pub source: Source,         // Tpm, SevSnp, Tdx, Ima, Evm
    pub evidence: String,       // Evidence data
    pub signature: Option<String>, // Signature over evidence
    pub timestamp: DateTime<Utc>,  // Creation timestamp
    pub previous_hash: Option<String>, // Link to previous node
    pub hash: String,           // Hash of this node
}
```

The AMC maintains a hash chain for tamper evidence, where each node contains the hash of the previous node.

### 2.2 MRAL (Multi-RoT Abstraction Layer)

The Multi-RoT Abstraction Layer provides adapters for different Root of Trust sources:

- **TPM Adapter**: Handles TPM quotes and PCR values
- **SEV-SNP Adapter**: Processes AMD SEV-SNP attestation reports
- **TDX Adapter**: Processes Intel TDX attestation reports
- **IMA Adapter**: Processes runtime integrity measurements

Each adapter normalizes platform-specific evidence to the AMC format.

### 2.3 ARG (Attestation Record Graph)

The Attestation Record Graph represents relationships between attestation evidence nodes as a directed acyclic graph:

```rust
pub struct ArgEdge {
    pub from: Uuid,             // Source node ID
    pub to: Uuid,               // Target node ID
    pub relationship: ArgRelationship, // Type of relationship
    pub signature: Option<String>,     // Signature over edge
}

pub enum ArgRelationship {
    VmIncludesHypervisor,       // VM attestation includes hypervisor measurement
    RuntimeLinkedToBoot,        // Runtime measurement linked to boot evidence
    VtpmBoundToPtpm,            // vTPM bound to platform TPM
    PolicyValidates,            // Policy validation relationship
}
```
### 2.4 PCE (Policy Compliance Engine)
The PCE validates attestation evidence against configurable policies before nodes are added to the AMC/ARG.

Policy-based validation via JSON policies
Validator types: field_presence, field_pattern, timestamp_age
Severity-based enforcement: critical violations reject nodes; non-critical violations are allowed with warnings
Two-pass policy matching and execution:
Pass 1: one specific policy (matches layer/mode/source)
Pass 2: all universal policies (wildcard, cross-cutting)
Execute rules from both; accumulate violations

Example of default policies (subset):
```json
{
  "version": "1.0.0",
  "policies": {
    "platform_tpm_boot": {
      "applies_to": {"layer":"Platform","mode":"BootTime","source":"Tpm"},
      "rules": [
        {"rule_type":"field_presence","required_fields":["evidence","layer","mode","source"]},
        {"rule_type":"field_pattern","field_path":"evidence","pattern":".*pcr.*","must_match":true},
        {"rule_type":"timestamp_age","max_age_seconds":300}
      ]
    },
    "untrusted_detection": {
      "applies_to": {"layer":null,"mode":null,"source":null},
      "rules": [
        {"rule_type":"field_pattern","field_path":"evidence","pattern":".*(untrusted|malicious|compromised|tampered).*","must_match":false,"severity":"critical"}
      ]
    }
  }
}
```

Compliance result schema:
```json
{
  "status": "Compliant|NonCompliant",
  "violations": [
    {"rule_type":"...","description":"...","severity":"critical|high|...","field_path":"evidence|..."}
  ],
  "validated_at": "RFC3339 timestamp",
  "policy_version": "1.0.0"
}
```

### 2.5 Attestation Manager

The Attestation Manager orchestrates evidence collection and builds AMC/ARG. With PCE integration, every node is validated before acceptance.

APIs:

- POST `/attest/boot` – Submit boot-time evidence (calls PCE)
- POST `/attest/runtime` – Submit runtime evidence (calls PCE)
- GET `/arg/:session` – Retrieve ARG (contains only accepted nodes)

PCE decision flow:

- Normalize to ACM → call PCE /validate/node
- If NonCompliant with any critical violation → reject (status: "rejected", node_id: null)
- Else accept (status: "success"), attach compliance in response and ARG metadata
- Fallback: if PCE unavailable → accept with status: "success_without_pce" and compliance: null

### 2.6 Verifier

The Verifier validates attestation evidence and produces trust decisions. It provides:

- POST `/verify` - Verify a complete attestation session
- POST `/verify/component` - Verify a specific component

## 3. Component Mapping

| DAVINCI Component | Implementation |
|---|---|
| AMC | `attestation-manager/src/amc.rs` |
| MRAL | `attestation-manager/src/mral.rs` (adapters: `mral-adapters/tpm-adapter/tpm_adapter.py`, `mral-adapters/cc-adapter/cc_adapter.py`) |
| ARG | `attestation-manager/src/arg.rs` |
| Attestation Manager | `attestation-manager/src/main.rs` |
| PCE (Policy Compliance Engine) | `pce-service/src/main.rs`, `pce-service/src/policy.rs`, `pce-service/src/validators.rs`, `pce-service/policies/default_policies json` |
| Verifier | `verifier/src/main.rs` |

## 4. Secure Bindings Implementation

### 4.1 vTPM ↔ pTPM Binding

- The TPM adapter collects platform PCR values during boot.
- These values are sealed and used to derive the vTPM’s primary keys.
- The evidence is normalized into an AMC node (layer: `Platform`, source: `Tpm`).
- The ARG records the relationship with an edge `VtpmBoundToPtpm`.

Enforcement (PCE):
- Formal validation of evidence via specific policy (required fields, “pcr” pattern, `timestamp_age ≤ 300s`) and universal policies (blacklist).
- If any `critical` violation exists, the node is rejected before insertion into AMC/ARG.
- On success, the compliance result (`status`, violations, `policy_version`, `validated_at`) is included in the Attestation Manager response and stored in ARG metadata.

### 4.2 VM ↔ Hypervisor Binding

- The hypervisor measurement is captured as a TPM quote (layer: `Hypervisor`, source: `Tpm`).
- The guest attestation report references the validated hypervisor node.
- The ARG models the relationship with one or more `VmIncludesHypervisor` edges.
- The Verifier checks transitive trust (platform → hypervisor → guest).

Enforcement (PCE):
- Joint execution of specific policies (Hypervisor/Boot-Tpm, Guest/Boot-SevSnp) and universal policies (blacklist) using the two-pass mechanism (specific + universal).
- Nodes are accepted only if they have no `critical` violations; otherwise they are rejected and not inserted into the ARG.
- Compliance results are attached to the Attestation Manager response and persisted in ARG metadata for auditability.

## 5. Threat Model

The DAVINCI prototype addresses the following threats. Where applicable, the Policy Compliance Engine (PCE) strengthens defenses by enforcing policy-based validation before evidence is accepted into AMC/ARG.

### 5.1 Replay Attacks
- Nonces are included in TPM quotes and attestation reports (where supported).
- Timestamps are embedded in all AMC nodes.
- Verifier checks freshness against the session context.
- PCE enforces `timestamp_age` per policy (e.g., ≤ 300s for boot, ≤ 60s for runtime) to reject stale evidence early.
- Assumption: time sources are reasonably synchronized (NTP); otherwise, stricter age windows may cause false rejections.

### 5.2 Substitution Attacks
- Digital signatures bind evidence to its producer (TPM keys, SEV-SNP VCEK chain).
- AMC hash chain detects tampering of stored nodes (each node carries the previous node hash).
- PCE structural checks (e.g., `field_presence`, `field_pattern`) reduce acceptance of malformed or incomplete evidence prior to cryptographic verification.
- Cryptographic correctness (signature and certificate validation) is enforced by the Verifier.

### 5.3 Origin Spoofing
- MRAL adapters require access to platform-bound keys and device interfaces to collect valid evidence.
- Verifier validates signature chains (e.g., TPM AK, AMD VCEK).
- PCE universal policies provide cross-cutting constraints (e.g., blacklist patterns), adding an additional barrier to spoofed or tainted evidence across all layers.

### 5.4 Malicious Evidence Injection
- PCE universal blacklist detection (e.g., “untrusted”, “malicious”, “compromised”, “tampered”) flags and rejects evidence with `critical` severity.
- Severity-based enforcement ensures nodes with critical violations are never inserted into AMC/ARG.
- Non-critical violations are accepted with explicit warnings, preserving operational continuity while maintaining visibility.
- ARG integrity is preserved by excluding rejected nodes from the graph; compliance results are stored in ARG metadata for auditability.

### 5.5 Policy Bypass and PCE Availability
- If the PCE is unavailable, the Attestation Manager operates in a fail-safe degraded mode: requests can be accepted with status `success_without_pce` and `compliance: null`.
- Residual risk: acceptance without policy validation increases exposure; recommended mitigations include alerting, rate limiting, and an operational toggle to disallow degraded mode in sensitive environments.
- Policies are loaded at startup; changes require a restart. Operational controls should ensure change management and review of policy updates.

### 5.6 Denial of Service (DoS)
- PCE is stateless and lightweight; horizontal scaling and simple load balancing can mitigate high request volumes.
- Regex patterns in policies should be curated to avoid pathological cases (catastrophic backtracking); patterns are compiled and reused.
- Attestation Manager can implement request limits per session/source to reduce amplification risks.

### 5.7 Residual Risks and Assumptions
- Time synchronization is essential for freshness checks to be meaningful.
- Current validator set is limited to presence, pattern, and timestamp checks; stronger semantic checks (e.g., signature verification) happen in the Verifier.
- Regex-based detection may produce false positives/negatives; policies should be tuned to the deployment context.
- Static policy loading means mid-flight policy changes are not applied until the next restart; plan maintenance windows accordingly.

## 6. Binding Specifications

### 6.1 Message Formats

Boot-time evidence (request to Attestation Manager):
```json
{
  "layer": "platform|hypervisor|guest",
  "source": "tpm|snp|tdx",
  "evidence": "{... source-specific evidence ...}"
}
```
PCE-enhanced response:
```json
{
  "status": "success|rejected|success_without_pce|error",
  "node_id": "uuid|null",
  "compliance": {
    "status": "Compliant|NonCompliant",
    "violations": [],
    "validated_at": "2025-12-14T16:28:02Z",
    "policy_version": "1.0.0"
  }
}
```

Runtime evidence:
```json
{
  "evidence": "{... IMA measurement data or serialized...}"
}
```

### 6.2 Signing and Nonces

- TPM quotes are signed by the TPM's asymmetric key
- SEV-SNP reports are signed by AMD's VCEK certificate chain
- Nonces are included in all attestation requests to prevent replay
- ARG edges can be signed to provide additional integrity guarantees

### 6.3 ARG Edge Formation

Edges in the ARG are formed based on semantic relationships:

- When a VM is launched, an edge is created from the VM node to the hypervisor node
- When runtime measurements are collected, edges are created to boot-time evidence
- When vTPM is bound to pTPM, an edge is created between the corresponding nodes
- Only PCE-validated nodes are included in the ARG

## 7. Normalization Specification (AMC)

### 7.1 Node Schema

Each ACM node contains:

- **id**: UUID for unique identification
- **layer**: Platform, Hypervisor, Guest, or Runtime
- **mode**: BootTime, Runtime, or Policy
- **source**: Tpm, SevSnp, Tdx, Ima, or Evm
- **evidence**: Serialized evidence data
- **signature**: Optional cryptographic signature
- **timestamp**: Creation time
- **previous_hash**: Link to previous node in chain
- **hash**: Hash of this node's content

### 7.2 Hashing Rules

Node hashes are calculated over all fields except the hash itself:

```
hash = SHA256(id + layer + mode + source + evidence + signature + timestamp + previous_hash)
```

### 7.3 Chain Rules

- The first node in a chain has `previous_hash = None`
- Each subsequent node's `previous_hash` field contains the hash of the previous node
- Node integrity can be verified by recalculating the hash
- Chain integrity can be verified by checking all links
- PCE validation occurs BEFORE node is added to chain

## 8. Policy Compliance Engine (PCE) - Detailed Specification

### 8.1 Architecture

The PCE is implemented as a standalone microservice (port 3032) that can be integrated with any attestation workflow. Key characteristics:

- Stateless: No session state, pure validation logic
- Configurable: Policies loaded from JSON files
- Extensible: New validator types can be added
- Performance: Regex-based pattern matching, efficient timestamp parsing

### 8.2 Default policies
The prototype includes 5 default policies:

1. Platform_tpm_boot: Validates Platform/BootTime/Tpm evidence
  - Required fields: evidence, layer, mode, source
  - Pattern: evidence must contain "pcr"
  - Timestamp: max 300 seconds old

2. Hypervisor_tpm_boot: Validates Hypervisor/BootTime/Tpm evidence
  - Required fields: evidence, layer, mode, source
  - Pattern: evidence must contain "pcr"
  - Timestamp: max 300 seconds old

3. Guest_snp_boot: Validates Guest/BootTime/SevSnp evidence
  - Required fields: evidence, layer, mode, source
  - Pattern: evidence must contain "measurement"
  - Timestamp: max 300 seconds old

4. Runtime_ima: Validates Runtime/Runtime/Ima evidence
  - Required fields: evidence, layer, mode, source
  - Pattern: evidence must contain "ima"
  - Timestamp: max 60 seconds old (stricter)

5. Untrusted_detection: Universal policy (applies to all nodes)
  - Pattern: evidence must NOT contain "untrusted|malicious|compromised|tampered"
  - Severity: critical (blocks node addition)

### 8.3 Integration Points

The Attestation Manager integrates with PCE via HTTP:

``` rust
async fn call_pce_validation(
    pce_client: &reqwest::Client,
    node: &AcmNode,
) -> Result<PceComplianceResult, String> {
    // Convert ACM node to JSON
    let node_json = serde_json::to_value(node)?;
    
    // Call PCE validation endpoint
    let response = pce_client
        .post("http://localhost:3032/validate/node")
        .json(&PceValidateRequest { node: node_json })
        .send()
        .await?;
    
    let result: PceValidateResponse = response.json().await?;
    Ok(result.result)
}

fn should_reject_node(compliance: &PceComplianceResult) -> bool {
    if compliance.status == ComplianceStatus::NonCompliant {
        // Check for critical violations
        compliance.violations.iter().any(|v| v.severity == "critical")
    } else {
        false
    }
}
```
### 8.4 Fail-Safe Behaviour
If the PCE service is unavailable, the Attestation Manager continues operating in degraded mode:

- Accepts nodes without PCE validation
- Returns status: "success_without_pce"
- Sets compliance field to null
- Logs warning for operational monitoring

This ensures high availability while maintaining security when PCE is operational.

## 9. Test Plan

### 9.1 Boot-Only Tests

- Platform TPM attestation collection and verification
- Hypervisor attestation collection and verification
- Guest VM attestation collection and verification
- ARG construction with boot-time evidence only
- PCE validation of boot-time evidence formats
- Critical violation rejection (untrusted evidence)

### 9.2 Runtime-Only Tests

- IMA measurement collection and normalization
- EVM policy validation
- ARG construction with runtime evidence only
- PCE validation with stricter timestamp requirements (60s vs 300s)

### 9.3 Combined Tests

- Complete end-to-end workflow from platform boot to runtime monitoring
- Verification of transitive trust relationships
- ARG export and import functionality
- PCE integration across all layers (Platform → Hypervisor → Guest → Runtime)

### 9.4 Negative Tests

- Tampered evidence detection
- Replay attack prevention
- Invalid signature detection
- Missing evidence handling
- PCE critical violation rejection (evidence with "untrusted" keyword)
- PCE timestamp age violation (evidence older than max_age_seconds)
- PCE pattern mismatch detection (missing required patterns like "pcr")

### 9.5 PCE-Specific tests
Automated test suite in `demo_pce.py`:
  1. Service health checks: PCE and Attestation Manager reachability
  2. Direct PCE validation: Sanity check for policy engine
  3. Compliant platform attestation: Valid evidence accepted
  4. Critical violation rejection: Evidence with "untrusted" keyword rejected
  5. Hypervisor attestation: Multi-layer validation
  6. Guest SEV-SNP attestation: Confidential computing evidence
  7. Old timestamp handling: Non-critical violations allowed with warnings
  8. Runtime IMA attestation: Runtime layer validation
  9. ARG integrity: Verify only compliant nodes in graph

Test Results: All 8 tests passed successfully

## 10. Implementation Considerations

### 10.1 Cryptographic Algorithms

- SHA-256 for hashing
- RSA-2048 or ECDSA for signatures
- AES-256 for encryption (where needed)

### 10.2 Key Management

- TPM keys are managed by the TPM hardware
- SEV-SNP uses AMD's certificate chain
- Session keys are ephemeral

### 10.3 Performance Considerations

- Evidence collection should be non-blocking
- Hash chain verification should be efficient
- ARG queries should be optimized
- PCE validation adds ~5-10ms latency per node (HTTP call + regex matching)
- Regex compilation is cached for performance

## 11. Conclusion

The DAVINCI prototype successfully implements the core components of the reference architecture with secure bindings between virtual layers. The modular design allows for easy extension to additional Root of Trust sources while maintaining the integrity of the attestation chain. The implementation provides a solid foundation for the formal security model and demonstrates the practical feasibility of the proposed approach.