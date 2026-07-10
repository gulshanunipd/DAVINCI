# 🔐 Attestation Manager & AMC - Analisi Completa

## 📖 Principi Concettuali e Funzionamento

### **Ruolo Architetturale**

#### **Attestation Manager**
È il **service orchestrator centrale** di DAVINCI. Gestisce:

1. **Evidence Collection**: Riceve evidence da MRAL adapters
2. **Privacy Enforcement**: Chiama PCE per trasformazioni obbligatorie
3. **AMC Construction**: Mantiene hash chain tamper-evident globale
4. **ARG Management**: Costruisce grafi di relazioni per-session
5. **API Gateway**: Espone REST endpoints per client esterni

#### **AMC (Abstract Measurement Chain)**
È la **rappresentazione canonica normalizzata** di tutto l'attestation evidence:

1. **Uniform Format**: Converte TPM/TDX/SEV-SNP/CCA in struttura comune
2. **Tamper Evidence**: Hash chain con `previous_hash` linking
3. **Multi-Layer Support**: Platform → Hypervisor → Guest → Runtime
4. **Cryptographic Binding**: Ogni node contiene hash di tutti i campi
5. **Global Log**: Persistenza sequenziale di tutti gli eventi

---

## 🏗️ **Architettura Attestation Manager**

### **Design Pattern: Multi-Session State Management**

```rust
AppState {
    amc_chain: Arc<Mutex<AcmChain>>,           // ← GLOBALE (cross-session)
    sessions: Arc<Mutex<HashMap<SessionState>>> // ← PER-SESSION (isolated ARG)
}

SessionState {
    arg: AttestationRecordGraph,               // ← Grafo relazioni
    last_boot_nodes: HashMap<Layer, Uuid>,     // ← Tracking parent edges
}
```

**Rationale**:
- **AMC globale**: Tamper evidence richiede sequenza unica immutabile
- **ARG per-session**: Ogni attestation flow ha dipendenze isolate
- **last_boot_nodes**: Permette edge creation automatica (Guest → Hypervisor → Platform)

---

### **Privacy-First Workflow**

```
Client Request → Attestation Manager → PCE Transform → AMC + ARG Storage
                                    ↓
                            ┌───────┴────────┐
                            │                │
                        SUCCESS          FAILURE
                            │                │
                    Privacy-protected   Graceful
                    Evidence stored     Degradation
                    (pseudonymized +    (Original
                     redacted)          evidence)
```

**Enforcement**:
1. **Prima** di inserire in AMC: Chiamata PCE `/privacy/transform`
2. **Se PCE OK**: Evidence trasformata → `status: "success"`
3. **Se PCE FAIL**: Fallback MRAL adapter → `status: "success_without_privacy"`
4. **Policy rejection** (da implementare): PCE `/validate/node` → reject node

---

## ✅ **IMPLEMENTATO (Attestation Manager)**

### **Core Components**

#### **1. HTTP Service (`main.rs`)** ✅
- [x] Warp-based REST API su porta 3030
- [x] CORS enabled (allow_any_origin)
- [x] Thread-safe state management (`Arc<Mutex<>>`)
- [x] HTTP client per PCE communication (`reqwest::Client`)

#### **2. API Endpoints** ✅

##### **POST /attest/boot** ✅

```rust
BootAttestationRequest {
    session_id: String,
    layer: "platform|hypervisor|guest",
    source: "tpm|snp|tdx|cca",
    evidence: String,  // Raw JSON evidence
}

BootAttestationResponse {
    status: "success|success_without_privacy|rejected|error",
    node_id: Option<Uuid>,
    privacy_manifest: Option<PceDisclosureManifest>,
    privacy_risks: Option<Vec<PcePrivacyRisk>>,
}
```

**Implementazione**:
- [x] Source mapping: `"tpm" → "Tpm"`, `"snp" → "SevSnp"`, etc.
- [x] PCE call con `call_pce_transformation()`
- [x] Success path: Evidence trasformata in AMC node
- [x] Failure path: Fallback a MRAL adapter (TpmAdapter, SnpAdapter)
- [x] AMC chain append con hash linking
- [x] ARG node insertion
- [x] Automatic edge creation:
  - Guest → Hypervisor: `VmIncludesHypervisor`
  - Hypervisor → Platform: `VmIncludesHypervisor`
- [x] `last_boot_nodes` update per layer tracking
- [x] Logging: Redacted fields count, risks detected

##### **POST /attest/runtime** ✅

```rust
RuntimeAttestationRequest {
    session_id: String,
    evidence: String,  // IMA-like runtime evidence
}

RuntimeAttestationResponse {
    status: "success|success_without_privacy|error",
    node_id: Option<Uuid>,
    privacy_manifest: Option<PceDisclosureManifest>,
    privacy_risks: Option<Vec<PcePrivacyRisk>>,
}
```

**Implementazione**:
- [x] Default PCE source: `"Tpm"` (IMA è TPM-based)
- [x] PCE transformation call
- [x] Success: Runtime node con `Layer::Runtime` + `Source::Ima`
- [x] Failure: Fallback a `ImaAdapter`
- [x] Edge creation: Runtime → Guest boot node (`RuntimeLinkedToBoot`)
- [x] Warning se guest boot node non trovato

##### **GET /arg/{session_id}** ✅

```rust
ArgResponse {
    arg: String,  // Serialized JSON del grafo
}
```

**Implementazione**:
- [x] Session lookup in HashMap
- [x] ARG serialization con `to_json()`
- [x] Fallback: Empty ARG se session non trovata
- [x] Logging: Session not found warning

#### **3. PCE Integration** ✅

```rust
async fn call_pce_transformation(
    client: &reqwest::Client,
    session_id: &str,
    source: &str,
    evidence: &str,
) -> Result<PceTransformResponse, String>
```

**Implementazione**:
- [x] HTTP POST a `http://localhost:3032/privacy/transform`
- [x] Request serialization (`PceTransformRequest`)
- [x] Response parsing con error handling
- [x] Timeout handling (implicit in reqwest)
- [x] Error propagation con `Result<>`

#### **4. Graceful Degradation** ✅

```rust
match pce_result {
    Ok(pce_response) => {
        // Use transformed evidence ✅
    },
    Err(e) => {
        // FALLBACK: Use MRAL adapter ✅
        let adapter = TpmAdapter::new();
        adapter.normalize_to_acm(&request.evidence)
    }
}
```

**Comportamento**:
- [x] PCE unavailable → Log warning
- [x] Original evidence used (NO privacy protections)
- [x] Status: `"success_without_privacy"`
- [x] `privacy_manifest: None`, `privacy_risks: None`
- [x] Node still inserted in AMC/ARG (availability prioritized)

#### **5. Edge Signature Generation** ✅ **(STUB)**

```rust
let edge = ArgEdge {
    from: node_id,
    to: parent_id,
    relationship: ArgRelationship::VmIncludesHypervisor,
    signature: Some(format!("sig_{}_{}", node_id, parent_id)),  // ← PLACEHOLDER
};
```

**Implementazione corrente**:
- [x] Signature field populated con string template
- [x] NOT cryptographically signed (formato `"sig_{from}_{to}"`)
- [x] Used for demonstration only

#### **6. Risk-Based Rejection** ✅ **(STUB)**

```rust
fn should_reject_evidence(_risks: &[PcePrivacyRisk]) -> bool {
    false  // ← ALWAYS FALSE (PCE handles risks)
}
```

**Implementazione corrente**:
- [x] Function exists ma sempre ritorna `false`
- [x] Commento: "PCE already applies protections"
- [x] No rejection logic implemented

---

## ✅ **IMPLEMENTATO (AMC - `amc.rs`)**

### **Core Data Structures**

#### **1. Node Structure** ✅

```rust
pub struct AcmNode {
    pub id: Uuid,                      // ✅ UUID v4
    pub layer: Layer,                  // ✅ Enum (Platform|Hypervisor|Guest|Runtime)
    pub mode: Mode,                    // ✅ Enum (BootTime|Runtime|Policy)
    pub source: Source,                // ✅ Enum (Tpm|SevSnp|Tdx|Ima|Evm)
    pub evidence: String,              // ✅ JSON serialized evidence
    pub signature: Option<String>,     // ✅ Optional digital signature
    pub timestamp: DateTime<Utc>,      // ✅ Chrono UTC timestamp
    pub previous_hash: Option<String>, // ✅ Link to previous node
    pub hash: String,                  // ✅ SHA-256 of all fields
}
```

**Implementazione**:
- [x] All fields serializable (`Serialize`, `Deserialize`)
- [x] UUID generation con `uuid::Uuid::new_v4()`
- [x] Timestamp auto-generated con `Utc::now()`
- [x] Hash calculated on creation
- [x] Enums con derive macros (Debug, Clone, PartialEq, Eq, Hash)

#### **2. Hash Calculation** ✅

```rust
fn calculate_hash(
    id: &Uuid,
    layer: &Layer,
    mode: &Mode,
    source: &Source,
    evidence: &str,
    signature: &Option<String>,
    timestamp: &DateTime<Utc>,
    previous_hash: &Option<String>,
) -> String {
    // Concatenate all fields → SHA-256 → hex encode
}
```

**Implementazione**:
- [x] Concatenazione di **tutti** i campi in String
- [x] SHA-256 con `openssl::hash::hash()`
- [x] Hex encoding con `hex::encode()`
- [x] Include conditional fields (signature, previous_hash)
- [x] Timestamp serialization con `to_rfc3339()`

#### **3. Node Integrity Verification** ✅

```rust
pub fn verify_integrity(&self) -> bool {
    let calculated_hash = Self::calculate_hash(...);
    calculated_hash == self.hash
}
```

**Implementazione**:
- [x] Re-calculates hash da campi correnti
- [x] Comparison con stored hash
- [x] Boolean return (true = intact, false = tampered)
- [x] Used in chain verification

#### **4. AMC Chain** ✅

```rust
pub struct AcmChain {
    pub nodes: Vec<AcmNode>,  // ✅ Sequential list
}

impl AcmChain {
    pub fn new() -> Self { /* ... */ }           // ✅
    pub fn add_node(&mut self, node: AcmNode)    // ✅
    pub fn verify_chain(&self) -> bool           // ✅
}
```

**Implementazione**:
- [x] `add_node()`: Auto-sets `previous_hash` from last node
- [x] `add_node()`: Recalculates node hash dopo linking
- [x] `verify_chain()`: Verifica ogni node integrity
- [x] `verify_chain()`: Verifica linkage sequence (i.previous_hash == i-1.hash)
- [x] First node check: `previous_hash == None`

#### **5. Unit Tests** ✅

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn test_node_creation() { /* ... */ }    // ✅
    
    #[test]
    fn test_chain_integrity() { /* ... */ }  // ✅
}
```

**Coverage**:
- [x] Node creation test
- [x] Node integrity verification test
- [x] Chain construction test (2 nodes)
- [x] Chain verification test

---

## ❌ **NON IMPLEMENTATO (Gap per Prototipo Completo)**

### **Critical Gaps - Attestation Manager**

#### **1. Policy Validation Integration** 🔴 **CRITICO (T2.3)**

**Problema**: PCE ha endpoint `/validate/node`, ma AM non lo chiama mai

**Cosa serve**:
```rust
// DOPO call_pce_transformation, PRIMA di add_node:
async fn call_pce_validation(
    client: &reqwest::Client,
    node: &AcmNode,
) -> Result<PceComplianceResult, String> {
    let request = PceValidateRequest {
        node: serde_json::to_value(node).unwrap(),
    };
    
    let response = client
        .post("http://localhost:3032/validate/node")
        .json(&request)
        .send()
        .await?;
    
    response.json().await
}

fn should_reject_node(compliance: &PceComplianceResult) -> bool {
    // Check for critical violations
    compliance.violations.iter().any(|v| v.severity == "critical")
}
```

**Codice da aggiungere**:
- [ ] `call_pce_validation()` in `main.rs`
- [ ] `PceValidateRequest` / `PceComplianceResult` structs
- [ ] Update `handle_boot_attestation()`: validation check PRIMA di AMC insert
- [ ] Update `handle_runtime_attestation()`: same validation
- [ ] Replace `should_reject_evidence()` stub con `should_reject_node()`
- [ ] Return `status: "rejected"` con compliance violations in response

**Impatto**: Nodi con `"untrusted"` keyword o policy violations vengono **accettati** invece di essere rifiutati

---

#### **2. Real ARG Edge Signatures** 🔴 **CRITICO (T2.1)**

**Problema**: Edge signatures sono placeholder string (`"sig_{from}_{to}"`)

**Cosa serve**:
```rust
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use openssl::hash::MessageDigest;

struct EdgeSigner {
    private_key: PKey<Private>,
}

impl EdgeSigner {
    fn sign_edge(&self, edge: &ArgEdge) -> Result<String, Error> {
        // 1. Serialize edge data
        let data = format!("{}:{}:{:?}", edge.from, edge.to, edge.relationship);
        
        // 2. Create signer
        let mut signer = Signer::new(MessageDigest::sha256(), &self.private_key)?;
        signer.update(data.as_bytes())?;
        
        // 3. Generate signature
        let signature = signer.sign_to_vec()?;
        
        Ok(hex::encode(signature))
    }
}

// In handle_boot_attestation():
let edge = ArgEdge {
    from: node_id,
    to: parent_id,
    relationship: ArgRelationship::VmIncludesHypervisor,
    signature: Some(edge_signer.sign_edge(&temp_edge)?),  // ← REAL SIGNATURE
};
```

**Codice da aggiungere**:
- [ ] `attestation-manager/src/crypto.rs`: EdgeSigner implementation
- [ ] Key generation at startup (ephemeral session key o persistent keypair)
- [ ] Integration in `AppState`: `edge_signer: Arc<EdgeSigner>`
- [ ] Update tutti gli `ArgEdge` creation points (3 locations)
- [ ] Public key export per Verifier verification

**Impatto**: ARG edges **non verificabili** crittograficamente → no binding proof

---

#### **3. Database Persistence** 🔴 **CRITICO (Production)**

**Problema**: AMC chain e ARG sono solo in-memory → persi al restart

**Cosa serve**:
```sql
-- PostgreSQL schema
CREATE TABLE amc_nodes (
    id UUID PRIMARY KEY,
    layer VARCHAR(50) NOT NULL,
    mode VARCHAR(50) NOT NULL,
    source VARCHAR(50) NOT NULL,
    evidence TEXT NOT NULL,
    signature TEXT,
    timestamp TIMESTAMP NOT NULL,
    previous_hash VARCHAR(64),
    hash VARCHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE arg_edges (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(255) NOT NULL,
    from_node UUID NOT NULL,
    to_node UUID NOT NULL,
    relationship VARCHAR(100) NOT NULL,
    signature TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    FOREIGN KEY (from_node) REFERENCES amc_nodes(id),
    FOREIGN KEY (to_node) REFERENCES amc_nodes(id)
);

CREATE INDEX idx_amc_timestamp ON amc_nodes(timestamp);
CREATE INDEX idx_arg_session ON arg_edges(session_id);
```

**Codice da aggiungere**:
- [ ] `Cargo.toml`: Add `sqlx` dependency
- [ ] `attestation-manager/src/db.rs`: Connection pool + queries
- [ ] `AcmChain::add_node()`: INSERT into amc_nodes
- [ ] `AttestationRecordGraph::add_node()`: INSERT into arg_nodes table
- [ ] `AttestationRecordGraph::add_edge()`: INSERT into arg_edges
- [ ] GET /arg/{session_id}: Query DB invece di in-memory HashMap
- [ ] Startup: Load existing chains from DB (recovery)

**Impatto**:
- No audit trail permanente
- Restart = data loss completo
- No forensics capability

---

#### **4. Nonce Management** 🟡 **MEDIUM (Security)**

**Problema**: Nonces menzionati in design ma non generati/verificati

**Cosa serve**:
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BootAttestationRequest {
    session_id: String,
    layer: String,
    source: String,
    evidence: String,
    nonce: Option<String>,  // ← ADD
}

// Generate nonce at session creation
fn generate_nonce() -> String {
    use rand::Rng;
    let bytes: Vec<u8> = (0..32).map(|_| rand::thread_rng().gen()).collect();
    hex::encode(bytes)
}

// Verify nonce in evidence
fn verify_nonce_in_evidence(evidence: &str, expected_nonce: &str) -> bool {
    // Parse evidence JSON, check nonce field matches
    if let Ok(ev) = serde_json::from_str::<serde_json::Value>(evidence) {
        if let Some(nonce) = ev.get("nonce").and_then(|v| v.as_str()) {
            return nonce == expected_nonce;
        }
    }
    false
}
```

**Codice da aggiungere**:
- [ ] `SessionState`: Add `nonce: String` field
- [ ] Session creation: Generate unique nonce
- [ ] `handle_boot_attestation()`: Verify nonce in evidence
- [ ] Reject evidence se nonce missing/mismatch
- [ ] Return nonce in session creation response

**Impatto**: Replay attack prevention **non funzionante**

---

#### **5. Freshness Validation** 🟡 **MEDIUM (Security)**

**Problema**: Timestamp nei nodes ma non verificato vs. current time

**Cosa serve**:
```rust
fn is_evidence_fresh(node_timestamp: &DateTime<Utc>, max_age_seconds: u64) -> bool {
    let now = Utc::now();
    let age = now.signed_duration_since(*node_timestamp);
    age.num_seconds() < max_age_seconds as i64
}

// In handle_boot_attestation, DOPO node creation:
if !is_evidence_fresh(&node.timestamp, 300) {  // 5 minutes
    println!("❌ Evidence TOO OLD: {} seconds", age);
    return Err(warp::reject::custom(StaleEvidenceError));
}
```

**Codice da aggiungere**:
- [ ] `is_evidence_fresh()` function
- [ ] Configurable max_age per layer/mode (boot=300s, runtime=60s)
- [ ] Integration in both boot/runtime handlers
- [ ] Custom rejection error: `StaleEvidenceError`
- [ ] Response status: `"rejected_stale"`

**Impatto**: Replay attacks con old evidence **non rilevati**

---

### **Non-Critical Gaps - Attestation Manager**

#### **6. Health Check Endpoint** 🟡

**Current**: Nessun `/health` endpoint  
**Missing**: Kubernetes liveness/readiness probes

```rust
let health_route = warp::path("health")
    .and(warp::get())
    .map(|| {
        warp::reply::json(&serde_json::json!({
            "status": "ok",
            "service": "attestation-manager",
            "version": env!("CARGO_PKG_VERSION"),
            "amc_nodes": state.amc_chain.lock().unwrap().nodes.len(),
            "active_sessions": state.sessions.lock().unwrap().len(),
        }))
    });
```

**Task**:
- [ ] Add `/health` endpoint
- [ ] Include service stats (nodes count, sessions count)
- [ ] PCE connectivity check (optional)

---

#### **7. Metrics & Observability** 🟡

**Current**: Solo `println!` logging  
**Missing**: Structured logging + Prometheus metrics

```rust
use tracing::{info, warn, error};
use prometheus::{Counter, Histogram, Registry};

lazy_static! {
    static ref BOOT_REQUESTS: Counter = 
        Counter::new("am_boot_requests_total", "Boot attestation requests").unwrap();
    
    static ref PCE_TRANSFORM_DURATION: Histogram = 
        Histogram::with_opts(HistogramOpts::new(
            "am_pce_transform_duration_seconds",
            "PCE transformation latency"
        )).unwrap();
}
```

**Task**:
- [ ] Replace `println!` con `tracing` macros
- [ ] Add Prometheus metrics
- [ ] `/metrics` endpoint per scraping
- [ ] Track: requests, latency, PCE failures, ARG edge count

---

#### **8. Rate Limiting per Session** 🟡

**Current**: No DoS protection  
**Missing**: Per-session request throttling

```rust
#[derive(Clone)]
struct SessionState {
    arg: AttestationRecordGraph,
    last_boot_nodes: HashMap<Layer, Uuid>,
    request_count: Arc<Mutex<usize>>,           // ← ADD
    last_request_time: Arc<Mutex<DateTime<Utc>>>, // ← ADD
}

fn check_rate_limit(session: &SessionState) -> Result<(), RateLimitError> {
    let mut count = session.request_count.lock().unwrap();
    let mut last_time = session.last_request_time.lock().unwrap();
    
    let now = Utc::now();
    let elapsed = now.signed_duration_since(*last_time).num_seconds();
    
    if elapsed > 60 {
        *count = 0;  // Reset after 1 minute
    }
    
    if *count >= 100 {  // Max 100 req/min per session
        return Err(RateLimitError);
    }
    
    *count += 1;
    *last_time = now;
    Ok(())
}
```

**Task**:
- [ ] Add rate limit fields to SessionState
- [ ] `check_rate_limit()` function
- [ ] Integration in handlers
- [ ] Return 429 Too Many Requests

---

### **Critical Gaps - AMC**

#### **9. Evidence Signature Verification** 🔴 **CRITICO (Security)**

**Problema**: `node.signature` field esiste ma non verificato mai

**Cosa serve**:
```rust
use openssl::x509::X509;
use openssl::pkey::PKey;
use openssl::sign::Verifier;

fn verify_node_signature(node: &AcmNode) -> Result<bool, Error> {
    let signature = node.signature.as_ref().ok_or("No signature")?;
    let signature_bytes = hex::decode(signature)?;
    
    // Extract public key from evidence (se è un certificate)
    let cert = extract_certificate_from_evidence(&node.evidence)?;
    let public_key = cert.public_key()?;
    
    // Verify signature
    let mut verifier = Verifier::new(MessageDigest::sha256(), &public_key)?;
    verifier.update(node.evidence.as_bytes())?;
    
    Ok(verifier.verify(&signature_bytes)?)
}
```

**Codice da aggiungere**:
- [ ] `amc.rs`: `verify_signature()` method su `AcmNode`
- [ ] Certificate extraction helper (TPM AIK cert, SEV-SNP VCEK)
- [ ] Public key extraction from PEM/DER
- [ ] Integration in `AcmChain::add_node()`: Reject unsigned/invalid
- [ ] Source-specific verification logic (TPM vs SNP vs TDX)

**Impatto**: **Qualsiasi** evidence può essere iniettato, anche non firmato

---

#### **10. Chain Persistence** 🔴 **CRITICO (Production)**

**Problema**: Same as AM DB persistence (duplicated perché stesso gap)

**Task**: See gap #3

---

#### **11. Chain Export/Import** 🟡

**Current**: No serialization oltre `Serialize` derive  
**Missing**: Complete chain export per forensics

```rust
impl AcmChain {
    pub fn export_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
    
    pub fn import_json(json: &str) -> Result<Self, serde_json::Error> {
        let chain: AcmChain = serde_json::from_str(json)?;
        
        // Verify integrity after import
        if !chain.verify_chain() {
            return Err(serde_json::Error::custom("Chain verification failed"));
        }
        
        Ok(chain)
    }
    
    pub fn export_to_file(&self, path: &str) -> Result<(), std::io::Error> {
        let json = self.export_json()?;
        std::fs::write(path, json)
    }
}
```

**Task**:
- [ ] `export_json()` method
- [ ] `import_json()` with verification
- [ ] File I/O methods
- [ ] CLI command: `am-tool export-chain --output chain.json`

---

### **Non-Critical Gaps - AMC**

#### **12. Merkle Tree Optimization** 🔵 **RESEARCH**

**Current**: Linear hash chain (O(n) verification)  
**Advanced**: Merkle tree (O(log n) proof)

**Concept**:
```rust
pub struct MerkleAmc {
    nodes: Vec<AcmNode>,
    merkle_tree: Vec<String>,  // Internal nodes
    root_hash: String,
}

impl MerkleAmc {
    pub fn prove_inclusion(&self, node_id: Uuid) -> MerkleProof {
        // Generate O(log n) proof path
    }
    
    pub fn verify_inclusion(&self, node: &AcmNode, proof: &MerkleProof) -> bool {
        // Verify without full chain
    }
}
```

**Task** (se richiesto per paper):
- [ ] Merkle tree implementation
- [ ] Proof generation
- [ ] Proof verification
- [ ] Benchmark: Chain vs Merkle verification time

---

## 📊 **Checklist Riepilogativa**

### **Attestation Manager - Functional Completeness**

| Component | Status | Priority |
|-----------|--------|----------|
| HTTP service (3 endpoints) | ✅ Done | - |
| PCE integration (/transform) | ✅ Done | - |
| Graceful degradation | ✅ Done | - |
| AMC chain construction | ✅ Done | - |
| ARG per-session management | ✅ Done | - |
| Automatic edge creation | ✅ Done | - |
| Session isolation | ✅ Done | - |
| **PCE validation integration** | ❌ Missing | 🔴 Critical |
| **Real ARG edge signatures** | ❌ Missing | 🔴 Critical |
| **DB persistence** | ❌ Missing | 🔴 Critical |
| **Nonce management** | ❌ Missing | 🟡 Medium |
| **Freshness validation** | ❌ Missing | 🟡 Medium |
| Health check endpoint | ❌ Missing | 🟡 Optional |
| Structured logging | ❌ Missing | 🟡 Optional |
| Rate limiting | ❌ Missing | 🟡 Optional |

### **AMC - Functional Completeness**

| Component | Status | Priority |
|-----------|--------|----------|
| Node structure (8 fields) | ✅ Done | - |
| Hash calculation (SHA-256) | ✅ Done | - |
| Node integrity verification | ✅ Done | - |
| Chain construction | ✅ Done | - |
| Chain verification | ✅ Done | - |
| Hash linking (previous_hash) | ✅ Done | - |
| Unit tests (2 tests) | ✅ Done | - |
| **Signature verification** | ❌ Missing | 🔴 Critical |
| **Chain persistence** | ❌ Missing | 🔴 Critical |
| Chain export/import | ❌ Missing | 🟡 Optional |
| Merkle tree optimization | ❌ Missing | 🔵 Research |

### **WP2 Deliverable Alignment**

| Requirement | Coverage |
|-------------|----------|
| **T2.1 Secure Bindings** | 50% (AMC linking OK, edge signatures placeholder, no sig verification) |
| **D3 Design Analysis** | 85% (workflow documented, security properties partially formalized) |
| **D4 Implementation Report** | 75% (core implemented, crypto verification missing) |

---

## 🎯 **Priorità per Completamento Prototipo**

### **Weekend 1-2: ARG Edge Signatures + Validation** (4 giorni)

1. **EdgeSigner implementation** (`crypto.rs`)
   - RSA-2048 keypair generation
   - Edge data serialization + signing
   - Integration in 3 edge creation points

2. **PCE validation integration**
   - `call_pce_validation()` in AM
   - Rejection logic per critical violations
   - Update response status handling

### **Weekend 3-4: Evidence Signature Verification** (4 giorni)

3. **Certificate extraction** (TPM AIK, SEV-SNP VCEK)
   - PEM/DER parsing
   - Public key extraction

4. **Signature verification** in `AcmNode`
   - RSA/ECDSA verification
   - Source-specific logic
   - Integration in `add_node()`

### **Weekend 5-6: DB Persistence** (4 giorni)

5. **PostgreSQL schema + migrations**
6. **AMC persistence** (INSERT on add_node)
7. **ARG persistence** (nodes + edges tables)
8. **Query layer** (GET /arg from DB)

### **Weekend 7-8: Security Hardening** (4 giorni)

9. **Nonce management** (generation + verification)
10. **Freshness validation** (timestamp checking)
11. **Audit logging** (structured events)

### **Weekend 9: Testing + Documentation** (2 giorni)

12. **End-to-end test**: Platform → Hypervisor → Guest → Runtime
13. **Integration test**: AM + PCE + Verifier
14. **Update reports**: D3 + D4 con implementation details

---

## 📝 **In Sintesi**

- **Attestation Manager**: ~75% implementato, mancano **3 critical gaps** (PCE validation, edge signatures, DB)
- **AMC**: ~80% implementato, manca **signature verification** (blocking T2.1)
- **Weekend 1-2** risolvono i 2 gap più critici per secure bindings (signatures + validation)
