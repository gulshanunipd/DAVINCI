# 🕸️ Attestation Record Graph (ARG) - Analisi Completa

## 📖 **Principi Concettuali e Funzionamento**

### **Ruolo Architetturale**

#### **ARG (Attestation Record Graph)**
È il **grafo di relazioni semantiche** tra attestation evidence nodes. Modella le dipendenze e i trust relationships nel sistema stratificato. Fornisce:
1. **Relationship Modeling**: Rappresenta bindings tra layer (Platform ↔ Hypervisor ↔ Guest ↔ Runtime)
2. **Transitive Trust**: Verifica catene di fiducia da VM a hardware RoT
3. **Compliance Tracking**: Associa metadata di policy validation a ogni node
4. **Graph Queries**: BFS/DFS per path finding e trust verification
5. **Auditability**: History completa di compliance evaluations

---

## 🏗️ **Architettura ARG**

### **Design Pattern: Directed Graph con Metadata**
```rust
AttestationRecordGraph {
    nodes: HashMap<Uuid, AcmNode>,           // ← Nodes indexed by ID
    edges: Vec<ArgEdge>,                     // ← All edges (sequential)
    metadata: HashMap<Uuid, NodeMetadata>,   // ← Policy compliance per node
    incoming_edges: HashMap<Uuid, Vec<usize>>, // ← Index: node → incoming edge indices
    outgoing_edges: HashMap<Uuid, Vec<usize>>, // ← Index: node → outgoing edge indices
}
```

**Rationale**:
- **HashMap nodes**: O(1) lookup per node ID
- **Vec edges**: Sequential storage, indexed access
- **Bidirectional indices**: O(1) neighbor queries senza scan completo edges
- **Separate metadata**: Compliance info decoupled da graph structure

---

### **Edge Semantics**

#### **ArgRelationship Types**
```rust
pub enum ArgRelationship {
    VmIncludesHypervisor,     // ← Guest → Hypervisor (layer dependency)
    RuntimeLinkedToBoot,      // ← Runtime → Guest (temporal dependency)
    VtpmBoundToPtpm,          // ← vTPM → pTPM (secure binding T2.1)
    PolicyValidates,          // ← Policy → Node (validation relationship)
}
```

**Semantica**:
- **VmIncludesHypervisor**: "Il Guest trust dipende da Hypervisor integrity"
- **RuntimeLinkedToBoot**: "Runtime measurement è consequence di boot state"
- **VtpmBoundToPtpm**: "vTPM keys derivate da pTPM PCRs"
- **PolicyValidates**: "Policy ha validato questo node" (unused currently)

---

### **Transitive Trust Model**

```
┌──────────────────────────────────────────┐
│  Transitive Trust Verification Flow      │
├──────────────────────────────────────────┤
│  Guest Node                              │
│     ↓ (VmIncludesHypervisor edge)        │
│  Hypervisor Node                         │
│     ↓ (VmIncludesHypervisor edge)        │
│  Platform Node (RoT)                     │
│                                          │
│  Trust = ∀ node ∈ path: valid(node) ∧   │
│           ∀ edge ∈ path: verified(edge) │
└──────────────────────────────────────────┘
```

**Property**: Se esiste path da node N a Platform RoT, e tutti i nodi/edge nel path sono validi, allora N è trusted

---

## ✅ **IMPLEMENTATO (arg.rs)**

### **Core Data Structures**

#### **1. ArgEdge** ✅
```rust
pub struct ArgEdge {
    pub from: Uuid,                      // ✅ Source node
    pub to: Uuid,                        // ✅ Target node
    pub relationship: ArgRelationship,   // ✅ Edge type
    pub signature: Option<String>,       // ✅ Cryptographic signature (optional)
}
```

**Implementazione**:
- [x] All fields public
- [x] Serializable (`Serialize`, `Deserialize`)
- [x] Signature field exists but **optional**
- [x] Direction: `from → to` (explicit directed edge)

---

#### **2. ArgRelationship** ✅
```rust
pub enum ArgRelationship {
    VmIncludesHypervisor,    // ✅
    RuntimeLinkedToBoot,     // ✅
    VtpmBoundToPtpm,         // ✅
    PolicyValidates,         // ✅
}
```

**Implementazione**:
- [x] 4 relationship types defined
- [x] `PartialEq` for equality checks
- [x] Serializable

**Usage status**:
- ✅ `VmIncludesHypervisor`: Used in Attestation Manager (Platform → Hypervisor → Guest)
- ✅ `RuntimeLinkedToBoot`: Used for IMA → Guest linkage
- ❌ `VtpmBoundToPtpm`: **Not used** (no vTPM detection logic)
- ❌ `PolicyValidates`: **Not used** (no policy → node edges created)

---

#### **3. AttestationRecordGraph** ✅
```rust
pub struct AttestationRecordGraph {
    pub nodes: HashMap<Uuid, AcmNode>,           // ✅
    pub edges: Vec<ArgEdge>,                     // ✅
    pub metadata: HashMap<Uuid, NodeMetadata>,   // ✅
    incoming_edges: HashMap<Uuid, Vec<usize>>,   // ✅ Private index
    outgoing_edges: HashMap<Uuid, Vec<usize>>,   // ✅ Private index
}
```

**Implementazione**:
- [x] Dual storage: nodes in HashMap, edges in Vec
- [x] Bidirectional edge indices (private, managed internally)
- [x] Metadata HashMap for compliance tracking
- [x] Serializable (full graph export)

---

### **Core Operations**

#### **4. Graph Construction** ✅

##### **add_node()** ✅
```rust
pub fn add_node(&mut self, node: AcmNode) {
    let node_id = node.id;
    self.nodes.insert(node_id, node);
    
    // Initialize empty metadata
    self.metadata.insert(node_id, NodeMetadata::new());
}
```

**Implementazione**:
- [x] Insert node in HashMap
- [x] Auto-initialize metadata (compliance: None)
- [x] No duplicate detection (overwrite if same ID)

---

##### **add_edge()** ✅
```rust
pub fn add_edge(&mut self, edge: ArgEdge) {
    let edge_index = self.edges.len();
    
    // Update bidirectional indices
    self.incoming_edges
        .entry(edge.to)
        .or_insert_with(Vec::new)
        .push(edge_index);
        
    self.outgoing_edges
        .entry(edge.from)
        .or_insert_with(Vec::new)
        .push(edge_index);
        
    self.edges.push(edge);
}
```

**Implementazione**:
- [x] Sequential edge storage (Vec)
- [x] Bidirectional index update
- [x] No cycle detection
- [x] No duplicate edge prevention

---

#### **5. Graph Queries** ✅

##### **get_incoming_edges()** ✅
```rust
pub fn get_incoming_edges(&self, node_id: &Uuid) -> Vec<&ArgEdge> {
    if let Some(indices) = self.incoming_edges.get(node_id) {
        indices.iter().map(|&i| &self.edges[i]).collect()
    } else {
        Vec::new()
    }
}
```

**Implementazione**:
- [x] O(1) index lookup
- [x] O(k) edge collection (k = number of incoming edges)
- [x] Return references (no cloning)
- [x] Empty Vec if node has no incoming edges

---

##### **get_outgoing_edges()** ✅
```rust
pub fn get_outgoing_edges(&self, node_id: &Uuid) -> Vec<&ArgEdge> {
    // Same as incoming, but uses outgoing_edges index
}
```

**Implementazione**:
- [x] Symmetric to `get_incoming_edges()`
- [x] O(1) + O(k) complexity

---

##### **get_neighbors()** ✅
```rust
pub fn get_neighbors(&self, node_id: &Uuid) -> HashSet<Uuid> {
    let mut neighbors = HashSet::new();
    
    // Collect from incoming edges
    if let Some(indices) = self.incoming_edges.get(node_id) {
        for &index in indices {
            neighbors.insert(self.edges[index].from);
        }
    }
    
    // Collect from outgoing edges
    if let Some(indices) = self.outgoing_edges.get(node_id) {
        for &index in indices {
            neighbors.insert(self.edges[index].to);
        }
    }
    
    neighbors
}
```

**Implementazione**:
- [x] HashSet per deduplication automatica
- [x] Both incoming and outgoing neighbors
- [x] Undirected neighborhood (treats graph as bidirectional)

---

#### **6. Graph Integrity** ✅

##### **verify_integrity()** ✅
```rust
pub fn verify_integrity(&self) -> bool {
    // Check all edges reference existing nodes
    for edge in &self.edges {
        if !self.nodes.contains_key(&edge.from) {
            return false;
        }
        if !self.nodes.contains_key(&edge.to) {
            return false;
        }
    }
    
    true
}
```

**Implementazione**:
- [x] Basic referential integrity check
- [x] Verifies: ∀ edge: edge.from ∈ nodes ∧ edge.to ∈ nodes
- [x] O(E) complexity (E = number of edges)

**Missing checks**:
- ❌ No cycle detection (DAG violation)
- ❌ No orphaned node detection
- ❌ No edge signature verification

---

#### **7. Serialization** ✅

##### **to_json() / from_json()** ✅
```rust
pub fn to_json(&self) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(self)
}

pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
    serde_json::from_str(json)
}
```

**Implementazione**:
- [x] Full graph serialization (nodes + edges + metadata + indices)
- [x] Pretty-print for human readability
- [x] Deserialization with type safety
- [x] No integrity check after import (should call `verify_integrity()`)

---

#### **8. Metadata Management** ✅

##### **set_node_metadata()** ✅
```rust
pub fn set_node_metadata(&mut self, node_id: Uuid, metadata: NodeMetadata) {
    self.metadata.insert(node_id, metadata);
}
```

**Implementazione**:
- [x] Direct HashMap insert
- [x] Overwrites existing metadata
- [x] No validation that node exists

---

##### **get_node_metadata()** ✅
```rust
pub fn get_node_metadata(&self, node_id: &Uuid) -> Option<&NodeMetadata> {
    self.metadata.get(node_id)
}
```

**Implementazione**:
- [x] O(1) lookup
- [x] Returns `None` if no metadata

---

##### **set_node_compliance()** ✅
```rust
pub fn set_node_compliance(&mut self, node_id: Uuid, compliance: ComplianceStatus) {
    if let Some(metadata) = self.metadata.get_mut(&node_id) {
        metadata.set_compliance(compliance);
    }
}
```

**Implementazione**:
- [x] Convenience method (no need to construct full metadata)
- [x] Archives previous compliance to history
- [x] Updates timestamp automatically
- [x] Silent if node not found

---

### **Transitive Trust Operations**

#### **9. find_path_to_platform()** ✅
```rust
pub fn find_path_to_platform(&self, start_node_id: &Uuid) -> Option<Vec<Uuid>> {
    // BFS to find shortest path to Platform layer
    // Uses outgoing edges (going "down" the stack)
    // Returns: Some(vec![start, intermediate..., platform]) or None
}
```

**Implementazione**:
- [x] Breadth-First Search (BFS) algorithm
- [x] Queue-based implementation (`VecDeque`)
- [x] Visited set per evitare cicli
- [x] Parent tracking per path reconstruction
- [x] Early termination quando raggiunge Platform layer
- [x] Path reversal per ordine corretto (start → platform)

**Complessità**:
- Time: O(V + E) worst case
- Space: O(V) per visited + parent maps

**Semantica**:
- Segue **outgoing edges** (from → to)
- Interpreta grafo come: Guest points to Hypervisor, Hypervisor points to Platform
- Ritorna **shortest path** (BFS property)

---

#### **10. verify_transitive_trust()** ✅
```rust
pub fn verify_transitive_trust(&self, node_id: &Uuid) -> bool {
    // 1. Find path to platform
    let path = match self.find_path_to_platform(node_id) {
        Some(p) => p,
        None => return false,
    };
    
    // 2. Verify all nodes in path exist
    for node_id in &path {
        if !self.nodes.contains_key(node_id) {
            return false;
        }
    }
    
    // 3. Verify all edges between consecutive nodes exist
    for i in 0..path.len() - 1 {
        let from = path[i];
        let to = path[i + 1];
        
        let has_edge = self.edges.iter().any(|e| e.from == from && e.to == to);
        
        if !has_edge {
            return false;
        }
    }
    
    true
}
```

**Implementazione**:
- [x] 3-step verification:
  1. Path existence check
  2. Node existence check
  3. Edge connectivity check
- [x] Boolean return (trusted / not trusted)
- [x] No signature verification (TODO)
- [x] No compliance verification (TODO)

**Missing verifications**:
- ❌ No edge signature verification
- ❌ No node compliance check (should verify all nodes are `Compliant`)
- ❌ No timestamp freshness check
- ❌ No AMC hash chain verification

---

### **Metadata Structures**

#### **11. NodeMetadata** ✅
```rust
pub struct NodeMetadata {
    pub compliance: Option<ComplianceStatus>,        // ✅ Current status
    pub compliance_history: Vec<ComplianceStatus>,   // ✅ Audit trail
    pub updated_at: DateTime<Utc>,                   // ✅ Last update timestamp
    pub custom: HashMap<String, serde_json::Value>,  // ✅ Extensibility
}
```

**Implementazione**:
- [x] `new()` constructor con defaults
- [x] `set_compliance()` con history archiving
- [x] Automatic timestamp update
- [x] Custom fields per future extensions

---

#### **12. ComplianceStatus** ✅
```rust
pub struct ComplianceStatus {
    pub status: ComplianceResult,           // ✅ Enum (Compliant/NonCompliant/Pending/Unknown)
    pub violations: Vec<PolicyViolation>,   // ✅ Detailed violations
    pub policy_version: String,             // ✅ Traceability
    pub validated_at: DateTime<Utc>,        // ✅ Timestamp
}
```

**Implementazione**:
- [x] Comprehensive compliance tracking
- [x] Violation details include: rule name, severity, field, expected/actual values
- [x] Policy version for auditing

---

#### **13. ComplianceResult** ✅
```rust
pub enum ComplianceResult {
    Compliant,       // ✅ Passed all rules
    NonCompliant,    // ✅ Failed one or more rules
    Pending,         // ✅ Validation in progress
    Unknown,         // ✅ No policy available
}
```

**Implementazione**:
- [x] 4 states defined
- [x] `PartialEq` for comparisons
- [x] Serializable

---

#### **14. PolicyViolation** ✅
```rust
pub struct PolicyViolation {
    pub rule_name: String,        // ✅ Violated rule identifier
    pub severity: String,         // ✅ "critical", "high", "medium", "low"
    pub description: String,      // ✅ Human-readable
    pub field: Option<String>,    // ✅ Problematic field
    pub expected: Option<String>, // ✅ Expected value
    pub actual: Option<String>,   // ✅ Actual value
}
```

**Implementazione**:
- [x] Rich violation details per debugging
- [x] Optional fields (not all violations are field-specific)
- [x] Severity classification

---

### **Unit Tests**

#### **15. test_arg_creation()** ✅
```rust
#[test]
fn test_arg_creation() {
    // Creates 3-node graph: Platform ← Hypervisor ← Guest
    // Adds 2 edges (VmIncludesHypervisor)
    // Verifies integrity
    // Checks neighbor count
}
```

**Coverage**:
- [x] Node addition
- [x] Edge addition
- [x] Integrity verification
- [x] Neighbor query

---

#### **16. test_arg_metadata()** ✅
```rust
#[test]
fn test_arg_metadata() {
    // Creates 2 nodes
    // Sets compliance metadata (Compliant)
    // Retrieves and verifies
    // Updates to NonCompliant with violation
    // Verifies history tracking (1 entry)
}
```

**Coverage**:
- [x] Metadata initialization
- [x] Compliance setting
- [x] Metadata retrieval
- [x] Compliance history

---

#### **17. test_arg_transitive_trust()** ✅
```rust
#[test]
fn test_arg_transitive_trust() {
    // Creates 3-node chain: Platform ← Hypervisor ← Guest
    // Adds edges
    // Finds path from Guest to Platform
    // Verifies path length (3 nodes)
    // Verifies path order (Guest → Hypervisor → Platform)
    // Verifies transitive trust for all nodes
}
```

**Coverage**:
- [x] Path finding (BFS)
- [x] Path length verification
- [x] Path order verification
- [x] Transitive trust verification

---

## ❌ **NON IMPLEMENTATO (Gap per Prototipo Completo)**

### **Critical Gaps**

#### **1. Edge Signature Verification** 🔴 **CRITICO (T2.1)**
**Problema**: `edge.signature` field exists but **never verified**

**Cosa serve**:
```rust
use openssl::pkey::PKey;
use openssl::sign::Verifier;
use openssl::hash::MessageDigest;

impl ArgEdge {
    pub fn verify_signature(&self, public_key: &PKey<openssl::pkey::Public>) -> Result<bool, Error> {
        let signature = self.signature.as_ref().ok_or("No signature")?;
        let signature_bytes = hex::decode(signature)?;
        
        // Serialize edge data (from + to + relationship)
        let data = format!("{}:{}:{:?}", self.from, self.to, self.relationship);
        
        // Verify signature
        let mut verifier = Verifier::new(MessageDigest::sha256(), public_key)?;
        verifier.update(data.as_bytes())?;
        
        Ok(verifier.verify(&signature_bytes)?)
    }
}

impl AttestationRecordGraph {
    pub fn verify_edge_signatures(&self, public_key: &PKey<openssl::pkey::Public>) -> bool {
        for edge in &self.edges {
            if let Some(_sig) = &edge.signature {
                if !edge.verify_signature(public_key).unwrap_or(false) {
                    return false;
                }
            }
        }
        true
    }
}
```

**Codice da aggiungere**:
- [ ] `ArgEdge::verify_signature()` method
- [ ] `AttestationRecordGraph::verify_edge_signatures()` method
- [ ] Integration in `verify_transitive_trust()` (verify edge signatures lungo path)
- [ ] Public key management (per-session key o global key)

**Impatto**: Edge signatures **non verificati** → tampering non rilevabile

---

#### **2. Cycle Detection** 🔴 **CRITICO (Security)**
**Problema**: No cycle detection → grafo può contenere loop

**Cosa serve**:
```rust
impl AttestationRecordGraph {
    pub fn detect_cycles(&self) -> Vec<Vec<Uuid>> {
        let mut cycles = Vec::new();
        let mut visited = HashSet::new();
        let mut rec_stack = HashSet::new();
        
        for node_id in self.nodes.keys() {
            if !visited.contains(node_id) {
                self.dfs_cycle_detect(*node_id, &mut visited, &mut rec_stack, &mut vec![], &mut cycles);
            }
        }
        
        cycles
    }
    
    fn dfs_cycle_detect(
        &self,
        node: Uuid,
        visited: &mut HashSet<Uuid>,
        rec_stack: &mut HashSet<Uuid>,
        path: &mut Vec<Uuid>,
        cycles: &mut Vec<Vec<Uuid>>,
    ) {
        visited.insert(node);
        rec_stack.insert(node);
        path.push(node);
        
        for edge in self.get_outgoing_edges(&node) {
            if !visited.contains(&edge.to) {
                self.dfs_cycle_detect(edge.to, visited, rec_stack, path, cycles);
            } else if rec_stack.contains(&edge.to) {
                // Cycle detected!
                let cycle_start = path.iter().position(|&n| n == edge.to).unwrap();
                cycles.push(path[cycle_start..].to_vec());
            }
        }
        
        rec_stack.remove(&node);
        path.pop();
    }
    
    pub fn is_dag(&self) -> bool {
        self.detect_cycles().is_empty()
    }
}
```

**Codice da aggiungere**:
- [ ] `detect_cycles()` con DFS algorithm
- [ ] `is_dag()` convenience method
- [ ] Integration in `add_edge()` (prevent cycle creation)
- [ ] Warning/error se cycle detected

**Impatto**: Circular dependencies possono causare infinite loops in path finding

---

#### **3. Compliance-Aware Trust Verification** 🔴 **CRITICO (T2.3)**
**Problema**: `verify_transitive_trust()` ignora compliance status

**Cosa serve**:
```rust
impl AttestationRecordGraph {
    pub fn verify_transitive_trust_with_compliance(&self, node_id: &Uuid) -> Result<bool, String> {
        let path = self.find_path_to_platform(node_id)
            .ok_or("No path to platform")?;
        
        // Verify all nodes exist
        for node_id in &path {
            if !self.nodes.contains_key(node_id) {
                return Err(format!("Node {} not found", node_id));
            }
        }
        
        // Verify all edges exist
        for i in 0..path.len() - 1 {
            let from = path[i];
            let to = path[i + 1];
            
            let has_edge = self.edges.iter().any(|e| e.from == from && e.to == to);
            
            if !has_edge {
                return Err(format!("Edge {} → {} not found", from, to));
            }
        }
        
        // NEW: Verify all nodes are compliant
        for node_id in &path {
            if let Some(metadata) = self.metadata.get(node_id) {
                if let Some(compliance) = &metadata.compliance {
                    if compliance.status != ComplianceResult::Compliant {
                        return Err(format!(
                            "Node {} is non-compliant: {} violations",
                            node_id,
                            compliance.violations.len()
                        ));
                    }
                } else {
                    return Err(format!("Node {} has no compliance status", node_id));
                }
            } else {
                return Err(format!("Node {} has no metadata", node_id));
            }
        }
        
        Ok(true)
    }
}
```

**Codice da aggiungere**:
- [ ] `verify_transitive_trust_with_compliance()` method
- [ ] Detailed error messages per debugging
- [ ] Integration in Verifier service
- [ ] Update test: `test_arg_transitive_trust_with_compliance()`

**Impatto**: Non-compliant nodes nella chain accettati come trusted

---

#### **4. Database Persistence** 🔴 **CRITICO (Production)**
**Problema**: ARG solo in-memory → perso al restart

**Cosa serve**:
```sql
-- PostgreSQL schema
CREATE TABLE arg_nodes (
    node_id UUID PRIMARY KEY,
    session_id VARCHAR(255) NOT NULL,
    amc_node_id UUID NOT NULL,  -- FK to amc_nodes
    created_at TIMESTAMP DEFAULT NOW(),
    FOREIGN KEY (amc_node_id) REFERENCES amc_nodes(id)
);

CREATE TABLE arg_edges (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(255) NOT NULL,
    from_node UUID NOT NULL,
    to_node UUID NOT NULL,
    relationship VARCHAR(100) NOT NULL,
    signature TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    FOREIGN KEY (from_node) REFERENCES arg_nodes(node_id),
    FOREIGN KEY (to_node) REFERENCES arg_nodes(node_id)
);

CREATE TABLE arg_metadata (
    node_id UUID PRIMARY KEY,
    compliance_status VARCHAR(50),
    compliance_violations JSONB,
    policy_version VARCHAR(50),
    validated_at TIMESTAMP,
    updated_at TIMESTAMP DEFAULT NOW(),
    custom_data JSONB,
    FOREIGN KEY (node_id) REFERENCES arg_nodes(node_id)
);

CREATE TABLE arg_compliance_history (
    id SERIAL PRIMARY KEY,
    node_id UUID NOT NULL,
    status VARCHAR(50) NOT NULL,
    violations JSONB,
    policy_version VARCHAR(50),
    validated_at TIMESTAMP NOT NULL,
    FOREIGN KEY (node_id) REFERENCES arg_nodes(node_id)
);

CREATE INDEX idx_arg_session ON arg_nodes(session_id);
CREATE INDEX idx_arg_edges_from ON arg_edges(from_node);
CREATE INDEX idx_arg_edges_to ON arg_edges(to_node);
```

**Codice da aggiungere**:
- [ ] `Cargo.toml`: Add `sqlx` dependency
- [ ] `attestation-manager/src/db/arg.rs`: DB layer
- [ ] `AttestationRecordGraph::save()` method
- [ ] `AttestationRecordGraph::load(session_id)` method
- [ ] Compliance history persistence
- [ ] Update Attestation Manager per usare DB-backed ARG

**Impatto**:
- No persistence cross-restart
- No audit trail permanente
- No forensics capability

---

#### **5. Orphaned Node Detection** 🟡 **MEDIUM**
**Problema**: Nodes possono esistere senza edges (orphans)

**Cosa serve**:
```rust
impl AttestationRecordGraph {
    pub fn find_orphaned_nodes(&self) -> Vec<Uuid> {
        let mut orphans = Vec::new();
        
        for node_id in self.nodes.keys() {
            let has_incoming = self.incoming_edges.contains_key(node_id);
            let has_outgoing = self.outgoing_edges.contains_key(node_id);
            
            if !has_incoming && !has_outgoing {
                orphans.push(*node_id);
            }
        }
        
        orphans
    }
    
    pub fn find_root_nodes(&self) -> Vec<Uuid> {
        // Nodes with no incoming edges (potential RoT)
        self.nodes.keys()
            .filter(|&id| !self.incoming_edges.contains_key(id))
            .copied()
            .collect()
    }
    
    pub fn find_leaf_nodes(&self) -> Vec<Uuid> {
        // Nodes with no outgoing edges
        self.nodes.keys()
            .filter(|&id| !self.outgoing_edges.contains_key(id))
            .copied()
            .collect()
    }
}
```

**Codice da aggiungere**:
- [ ] `find_orphaned_nodes()` method
- [ ] `find_root_nodes()` method
- [ ] `find_leaf_nodes()` method
- [ ] Warning se orphans detected
- [ ] Integration in `verify_integrity()`

**Impatto**: Orphaned nodes indicano errori di construction

---

#### **6. Path Caching** 🟡 **MEDIUM (Performance)**
**Problema**: `find_path_to_platform()` ricalcolato ogni volta

**Cosa serve**:
```rust
use std::cell::RefCell;

pub struct AttestationRecordGraph {
    // ... existing fields ...
    
    // Cache: node_id → path to platform
    path_cache: RefCell<HashMap<Uuid, Vec<Uuid>>>,
}

impl AttestationRecordGraph {
    pub fn find_path_to_platform(&self, start_node_id: &Uuid) -> Option<Vec<Uuid>> {
        // Check cache first
        if let Some(cached) = self.path_cache.borrow().get(start_node_id) {
            return Some(cached.clone());
        }
        
        // Compute path (existing BFS logic)
        let path = /* ... BFS ... */;
        
        // Cache result
        if let Some(ref p) = path {
            self.path_cache.borrow_mut().insert(*start_node_id, p.clone());
        }
        
        path
    }
    
    pub fn invalidate_path_cache(&mut self) {
        // Call when graph structure changes
        self.path_cache.borrow_mut().clear();
    }
    
    pub fn add_edge(&mut self, edge: ArgEdge) {
        // ... existing logic ...
        self.invalidate_path_cache();
    }
}
```

**Codice da aggiungere**:
- [ ] `path_cache` field con `RefCell<HashMap>`
- [ ] Cache check in `find_path_to_platform()`
- [ ] `invalidate_path_cache()` method
- [ ] Call invalidation in `add_edge()` and `add_node()`

**Impatto**: Repeated path queries slow (O(V+E) ogni volta)

---

### **Non-Critical Gaps**

#### **7. Graph Visualization Export** 🔵 **NICE-TO-HAVE**
**Current**: Solo JSON export
**Missing**: DOT format per Graphviz

```rust
impl AttestationRecordGraph {
    pub fn to_dot(&self) -> String {
        let mut dot = String::from("digraph ARG {\n");
        dot.push_str("  rankdir=BT;\n");  // Bottom-to-top (Platform at top)
        
        // Nodes
        for (id, node) in &self.nodes {
            let label = format!("{:?}\\n{:?}", node.layer, node.source);
            let color = match node.layer {
                Layer::Platform => "green",
                Layer::Hypervisor => "blue",
                Layer::Guest => "orange",
                Layer::Runtime => "red",
            };
            
            dot.push_str(&format!(
                "  \"{}\" [label=\"{}\", color={}, style=filled, fillcolor={}];\n",
                id, label, color, color
            ));
        }
        
        // Edges
        for edge in &self.edges {
            let style = match edge.relationship {
                ArgRelationship::VmIncludesHypervisor => "solid",
                ArgRelationship::RuntimeLinkedToBoot => "dashed",
                ArgRelationship::VtpmBoundToPtpm => "bold",
                ArgRelationship::PolicyValidates => "dotted",
            };
            
            dot.push_str(&format!(
                "  \"{}\" -> \"{}\" [style={}, label=\"{:?}\"];\n",
                edge.from, edge.to, style, edge.relationship
            ));
        }
        
        dot.push_str("}\n");
        dot
    }
}
```

**Task**:
- [ ] `to_dot()` method
- [ ] Color coding per layer
- [ ] Style differentiation per relationship type
- [ ] CLI tool: `arg-visualize session_123.json > graph.dot`

---

#### **8. Subgraph Extraction** 🔵 **NICE-TO-HAVE**
**Current**: No subgraph queries
**Missing**: Extract nodes within N hops

```rust
impl AttestationRecordGraph {
    pub fn extract_subgraph(&self, center_node: &Uuid, max_hops: usize) -> Self {
        let mut subgraph = AttestationRecordGraph::new();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        
        queue.push_back((*center_node, 0));  // (node_id, distance)
        visited.insert(*center_node);
        
        while let Some((node_id, dist)) = queue.pop_front() {
            if dist > max_hops {
                continue;
            }
            
            // Add node to subgraph
            if let Some(node) = self.nodes.get(&node_id) {
                subgraph.add_node(node.clone());
            }
            
            // Add edges and traverse neighbors
            for edge in self.get_outgoing_edges(&node_id) {
                subgraph.add_edge(edge.clone());
                
                if !visited.contains(&edge.to) {
                    visited.insert(edge.to);
                    queue.push_back((edge.to, dist + 1));
                }
            }
            
            for edge in self.get_incoming_edges(&node_id) {
                subgraph.add_edge(edge.clone());
                
                if !visited.contains(&edge.from) {
                    visited.insert(edge.from);
                    queue.push_back((edge.from, dist + 1));
                }
            }
        }
        
        subgraph
    }
}
```

**Task**:
- [ ] `extract_subgraph()` method
- [ ] BFS con distance limit
- [ ] Use case: Focus on Guest + immediate dependencies

---

#### **9. Relationship Type Filtering** 🔵 **NICE-TO-HAVE**
**Current**: No edge filtering by relationship type
**Missing**: Query edges by type

```rust
impl AttestationRecordGraph {
    pub fn get_edges_by_relationship(&self, rel_type: &ArgRelationship) -> Vec<&ArgEdge> {
        self.edges.iter()
            .filter(|e| &e.relationship == rel_type)
            .collect()
    }
    
    pub fn find_path_with_relationship(
        &self,
        start: &Uuid,
        end: &Uuid,
        allowed_relationships: &[ArgRelationship],
    ) -> Option<Vec<Uuid>> {
        // BFS that only follows edges with allowed relationship types
        // ...
    }
}
```

**Task**:
- [ ] `get_edges_by_relationship()` method
- [ ] `find_path_with_relationship()` method
- [ ] Use case: Find path usando solo `VmIncludesHypervisor` edges

---

#### **10. Comprehensive Test Suite** 🟡
**Current**: 3 basic tests
**Missing**: Edge cases + performance tests

```rust
#[cfg(test)]
mod tests {
    // Existing tests ✅
    
    // Missing tests:
    #[test]
    fn test_orphaned_nodes() { /* ... */ }
    
    #[test]
    fn test_cycle_detection() { /* ... */ }
    
    #[test]
    fn test_edge_signature_verification() { /* ... */ }
    
    #[test]
    fn test_compliance_aware_trust() { /* ... */ }
    
    #[test]
    fn test_path_caching_performance() { /* ... */ }
    
    #[test]
    fn test_large_graph_performance() {
        // 10,000 nodes, 50,000 edges
        // Benchmark: add_node, add_edge, find_path_to_platform
    }
    
    #[test]
    fn test_malformed_graph() {
        // Edges pointing to non-existent nodes
        assert!(!arg.verify_integrity());
    }
}
```

**Task**:
- [ ] Edge case tests
- [ ] Error handling tests
- [ ] Performance benchmarks
- [ ] Malformed graph tests

---

## 📊 **Checklist Riepilogativa**

### **AttestationRecordGraph - Functional Completeness**
| Component | Status | Priority |
|-----------|--------|----------|
| ArgEdge structure | ✅ Done | - |
| ArgRelationship enum (4 types) | ✅ Done | - |
| Graph structure (HashMap + Vec + indices) | ✅ Done | - |
| add_node() | ✅ Done | - |
| add_edge() | ✅ Done | - |
| get_incoming_edges() | ✅ Done | - |
| get_outgoing_edges() | ✅ Done | - |
| get_neighbors() | ✅ Done | - |
| verify_integrity() (basic) | ✅ Done | - |
| to_json() / from_json() | ✅ Done | - |
| NodeMetadata structure | ✅ Done | - |
| ComplianceStatus tracking | ✅ Done | - |
| find_path_to_platform() (BFS) | ✅ Done | - |
| verify_transitive_trust() (basic) | ✅ Done | - |
| Unit tests (3 tests) | ✅ Done | - |
| **Edge signature verification** | ❌ Missing | 🔴 Critical |
| **Cycle detection** | ❌ Missing | 🔴 Critical |
| **Compliance-aware trust verification** | ❌ Missing | 🔴 Critical |
| **Database persistence** | ❌ Missing | 🔴 Critical |
| **Orphaned node detection** | ❌ Missing | 🟡 Medium |
| **Path caching** | ❌ Missing | 🟡 Medium |
| DOT export (Graphviz) | ❌ Missing | 🔵 Nice-to-have |
| Subgraph extraction | ❌ Missing | 🔵 Nice-to-have |
| Relationship filtering | ❌ Missing | 🔵 Nice-to-have |
| Comprehensive tests | ❌ Missing | 🟡 Optional |

### **WP2 Deliverable Alignment**
| Requirement | Coverage |
|-------------|----------|
| **T2.1 Secure Bindings** | 50% (structure OK, edge signatures placeholder, no verification) |
| **T2.3 Security Model** | 60% (transitive trust model implemented, compliance integration missing) |
| **D3 Design Analysis** | 85% (ARG architecture fully documented) |
| **D4 Implementation Report** | 70% (core graph operations working, crypto verification missing) |

---

## 🎯 **Priorità per Completamento Prototipo**

### **Weekend 1-2: Edge Signatures + Cycle Detection** (4 giorni)
1. **Real edge signature generation** (Attestation Manager)
   - RSA-2048 signing in `add_edge()` calls
   - Integration con `EdgeSigner` (vedi Attestation Manager gap #2)
   
2. **Edge signature verification** (ARG)
   - `ArgEdge::verify_signature()` method
   - `AttestationRecordGraph::verify_edge_signatures()` method
   - Integration in `verify_transitive_trust()`
   
3. **Cycle detection**
   - `detect_cycles()` con DFS algorithm
   - `is_dag()` convenience method
   - Warning/error se cycle detected

### **Weekend 3-4: Compliance Integration** (4 giorni)
4. **Compliance-aware trust verification**
   - `verify_transitive_trust_with_compliance()` method
   - Reject path se any node is NonCompliant
   - Detailed error reporting
   
5. **Metadata validation**
   - Check che tutti i nodes hanno metadata
   - Warning se compliance status missing

### **Weekend 5-6: Database Persistence** (4 giorni)
6. **PostgreSQL schema** (tables: arg_nodes, arg_edges, arg_metadata, compliance_history)
7. **ARG persistence layer** (save/load methods)
8. **Query optimization** (indices su session_id, from_node, to_node)

### **Weekend 7-8: Advanced Features** (4 giorni)
9. **Orphaned node detection** + root/leaf finding
10. **Path caching** per performance
11. **DOT export** per visualization

---

## 💡 **Architectural Decisions Rationale**

### **Why Bidirectional Indices?**
- **Performance**: O(1) neighbor lookup senza scan completo edges
- **Use case**: Transitive trust verification richiede frequent neighbor queries

### **Why Separate Metadata?**
- **Decoupling**: Graph structure vs policy evaluation sono concerns separati
- **Scalability**: Metadata può crescere (compliance history) senza impattare graph structure

### **Why BFS for Path Finding?**
- **Shortest path**: BFS guarantees shortest path (minimo numero di hops)
- **Use case**: Trust chain più breve = meno attack surface

### **Why Per-Session ARG?**
- **Isolation**: Ogni attestation session ha dipendenze isolate
- **Privacy**: Cross-session correlation prevention

---

**In sintesi**:
- **ARG**: ~75% implementato (graph operations complete, crypto verification missing)
- **Critical gap**: Edge signature verification è **blocco totale** per T2.1 secure bindings
- **Priorità**: Weekend 1-2 risolvono edge signatures + cycle detection (fundational security)
- **Performance**: Path caching opzionale ma raccomandato per production scale
