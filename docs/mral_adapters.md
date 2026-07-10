# 🔌 MRAL Adapters - Analisi Completa

## 📖 **Principi Concettuali e Funzionamento**

### **Ruolo Architetturale**

#### **MRAL (Multi-RoT Abstraction Layer)**
È il **layer di normalizzazione** tra hardware RoT eterogenei e il formato AMC canonico. Fornisce:
1. **Hardware Abstraction**: Interfaccia uniforme per TPM/SEV-SNP/TDX/CCA/IMA
2. **Evidence Collection**: Interroga hardware RoT per ottenere attestation data
3. **Format Normalization**: Converte formati vendor-specific in `AcmNode`
4. **Signature Preservation**: Mantiene firme crittografiche originali
5. **Graceful Degradation**: Fallback se hardware non disponibile

---

## 🏗️ **Architettura MRAL**

### **Design Pattern: Trait-Based Adapters (Rust)**
```rust
pub trait MralAdapter {
    fn normalize_to_acm(&self, evidence: &str) -> Result<AcmNode, String>;
}

// Implementations:
// - TpmAdapter (Layer::Platform, Source::Tpm)
// - SnpAdapter (Layer::Guest, Source::SevSnp)
// - TdxAdapter (Layer::Guest, Source::Tdx)
// - ImaAdapter (Layer::Runtime, Source::Ima)
```

**Rationale**:
- **Uniform Interface**: Tutti gli adapter espongono stesso metodo `normalize_to_acm()`
- **Extensibility**: Aggiungere nuovo RoT = implementare trait
- **Type Safety**: Rust garantisce compilazione solo se trait completo

### **Design Pattern: Class-Based Adapters (Python)**
```python
class TpmAdapter:
    def collect_pcrs() -> Dict[str, Any]
    def collect_quote() -> Dict[str, Any]
    def normalize_to_acm() -> Dict[str, Any]

class CcAdapter:
    def __init__(platform: "snp|tdx")
    def collect_attestation_report() -> Dict[str, Any]
    def normalize_to_acm() -> Dict[str, Any]
```

**Rationale**:
- **Hardware Interaction**: Python più flessibile per subprocess/device I/O
- **Prototyping**: Rapid development per adapter simulated
- **Separation**: Rust adapters = normalization only, Python = collection + normalization

---

## ✅ **IMPLEMENTATO (Rust Adapters - `mral.rs`)**

### **Core Structures**

#### **1. Evidence Types** ✅
```rust
// TPM Evidence
pub struct TpmQuote {
    pub pcrs: Vec<TpmPcr>,      // ✅ PCR values (index + value)
    pub signature: String,       // ✅ TPM AIK signature
    pub quote: String,           // ✅ Quote data
}

pub struct TpmPcr {
    pub index: u32,              // ✅ PCR index (0-23)
    pub value: String,           // ✅ PCR hash (hex)
}

// SEV-SNP Evidence
pub struct SnpReport {
    pub data: String,            // ✅ Report data
    pub signature: String,       // ✅ VCEK signature
    pub platform_info: String,   // ✅ Platform metadata
    pub policy: String,          // ✅ Guest policy
}

// Intel TDX Evidence
pub struct TdxReport {
    pub td_report: String,       // ✅ TD Report
    pub td_quote: String,        // ✅ TD Quote
}

// IMA Evidence
pub struct ImaMeasurement {
    pub path: String,            // ✅ File path
    pub hash: String,            // ✅ File hash
    pub template_hash: String,   // ✅ Template hash
    pub timestamp: String,       // ✅ Measurement timestamp
}
```

**Implementazione**:
- [x] Tutte le struct con `Serialize`, `Deserialize`
- [x] Derive macros: `Debug`, `Clone`
- [x] Fields pubblici per easy access

---

#### **2. MralAdapter Trait** ✅
```rust
pub trait MralAdapter {
    fn normalize_to_acm(&self, evidence: &str) -> Result<AcmNode, String>;
}
```

**Implementazione**:
- [x] Single method interface
- [x] Input: JSON string (raw evidence)
- [x] Output: `Result<AcmNode, String>` (success/error)
- [x] Error handling con descriptive messages

---

#### **3. TpmAdapter** ✅
```rust
pub struct TpmAdapter;

impl MralAdapter for TpmAdapter {
    fn normalize_to_acm(&self, evidence: &str) -> Result<AcmNode, String> {
        // 1. Parse JSON → TpmQuote
        let quote: TpmQuote = serde_json::from_str(evidence)?;
        
        // 2. Create AcmNode with:
        //    - Layer::Platform (or Hypervisor)
        //    - Mode::BootTime
        //    - Source::Tpm
        //    - signature: quote.signature
        
        Ok(node)
    }
}
```

**Implementazione**:
- [x] `TpmAdapter::new()` constructor
- [x] JSON parsing con `serde_json::from_str`
- [x] Error propagation con `?` operator
- [x] Signature extraction da `TpmQuote`
- [x] Default layer: `Platform` (comment: "or Hypervisor depending on context")
- [x] Hardcoded `Mode::BootTime`, `Source::Tpm`

**Limitazioni correnti**:
- ⚠️ Layer sempre `Platform` (no dynamic detection)
- ⚠️ No PCR validation
- ⚠️ No signature verification (only extraction)

---

#### **4. SnpAdapter** ✅
```rust
pub struct SnpAdapter;

impl MralAdapter for SnpAdapter {
    fn normalize_to_acm(&self, evidence: &str) -> Result<AcmNode, String> {
        let report: SnpReport = serde_json::from_str(evidence)?;
        
        let node = AcmNode::new(
            Layer::Guest,           // ✅ Hardcoded Guest
            Mode::BootTime,         // ✅
            Source::SevSnp,         // ✅
            evidence.to_string(),
            Some(report.signature), // ✅ VCEK signature
            None,
        );
        
        Ok(node)
    }
}
```

**Implementazione**:
- [x] `SnpAdapter::new()` constructor
- [x] JSON parsing → `SnpReport`
- [x] Layer: `Guest` (SEV-SNP è VM-level)
- [x] Signature extraction

---

#### **5. TdxAdapter** ✅
```rust
pub struct TdxAdapter;

impl MralAdapter for TdxAdapter {
    fn normalize_to_acm(&self, evidence: &str) -> Result<AcmNode, String> {
        let _report: TdxReport = serde_json::from_str(evidence)?;
        
        let node = AcmNode::new(
            Layer::Guest,
            Mode::BootTime,
            Source::Tdx,
            evidence.to_string(),
            None,  // ⚠️ No signature (comment: "might have different signature structures")
            None,
        );
        
        Ok(node)
    }
}
```

**Implementazione**:
- [x] `TdxAdapter::new()` constructor
- [x] JSON parsing → `TdxReport`
- [x] Layer: `Guest`
- [x] **Signature: None** (TODO: extract from TD Quote)

**Limitazione**:
- ❌ TDX quote signatures **non estratte**
- Comment indica awareness: "might have different signature structures"

---

#### **6. ImaAdapter** ✅
```rust
pub struct ImaAdapter;

impl MralAdapter for ImaAdapter {
    fn normalize_to_acm(&self, evidence: &str) -> Result<AcmNode, String> {
        let _measurement: ImaMeasurement = serde_json::from_str(evidence)?;
        
        let node = AcmNode::new(
            Layer::Runtime,   // ✅ IMA = runtime layer
            Mode::Runtime,    // ✅
            Source::Ima,      // ✅
            evidence.to_string(),
            None,             // ⚠️ IMA measurements typically unsigned
            None,
        );
        
        Ok(node)
    }
}
```

**Implementazione**:
- [x] `ImaAdapter::new()` constructor
- [x] JSON parsing → `ImaMeasurement`
- [x] Correct layer: `Runtime`
- [x] Correct mode: `Runtime`
- [x] No signature (IMA measurements non firmati di default)

---

#### **7. Unit Tests** ✅
```rust
#[cfg(test)]
mod tests {
    #[test]
    fn test_tpm_adapter() {
        let adapter = TpmAdapter::new();
        let sample_quote = r#"{...}"#;
        let result = adapter.normalize_to_acm(sample_quote);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_snp_adapter() {
        let adapter = SnpAdapter::new();
        let sample_report = r#"{...}"#;
        let result = adapter.normalize_to_acm(sample_report);
        assert!(result.is_ok());
    }
}
```

**Coverage**:
- [x] `test_tpm_adapter`: Sample TPM quote with 2 PCRs
- [x] `test_snp_adapter`: Sample SNP report
- [x] Basic success assertion (`result.is_ok()`)

**Missing tests**:
- ❌ TDX adapter test
- ❌ IMA adapter test
- ❌ Error handling tests (malformed JSON)
- ❌ Signature verification tests

---

## ✅ **IMPLEMENTATO (Python Adapters)**

### **TPM Adapter (`tpm_adapter.py`)**

#### **1. Class Structure** ✅
```python
class TpmAdapter:
    def __init__(self, use_simulator: bool = True):
        self.use_simulator = use_simulator
        self.tpm_device = "/dev/tpm0" if not use_simulator else None
```

**Implementazione**:
- [x] Constructor con simulator flag
- [x] Device path configuration (`/dev/tpm0`)
- [x] Default: `use_simulator=True` (no hardware dependency)

---

#### **2. PCR Collection** ✅
```python
def collect_pcrs(self, pcr_indices: list = None) -> Dict[str, Any]:
    if pcr_indices is None:
        pcr_indices = list(range(24))  # PCR 0-23
    
    pcrs = {}
    for pcr_index in pcr_indices:
        # SIMULATED: pcr_value = hashlib.sha256(f"simulated_pcr_{pcr_index}".encode()).hexdigest()
        pcrs[str(pcr_index)] = pcr_value
    
    return pcrs
```

**Implementazione**:
- [x] Method signature corretta
- [x] Default: All 24 PCRs
- [x] Return: Dict `{"0": "hash", "1": "hash", ...}`
- [x] **SIMULATED**: SHA-256 di stringa `"simulated_pcr_{index}"`
- [x] Comment chiaro: "In a real implementation, this would use TPM libraries like tpm2-tools"

**Limitazione**:
- ❌ No real TPM interaction (`tpm2_pcrread`)
- ❌ No error handling per TPM unavailable

---

#### **3. Quote Collection** ✅
```python
def collect_quote(self, pcr_indices: list = None, nonce: str = "") -> Dict[str, Any]:
    if pcr_indices is None:
        pcr_indices = list(range(8))  # PCR 0-7 by default
    
    pcrs = self.collect_pcrs(pcr_indices)
    
    quote_data = {
        "pcrs": pcrs,
        "nonce": nonce,
        "timestamp": self._get_timestamp()
    }
    
    quote_string = json.dumps(quote_data, sort_keys=True)
    signature = self._simulate_signature(quote_string)
    
    return {
        "quote": quote_data,
        "signature": signature,
        "raw": quote_string
    }
```

**Implementazione**:
- [x] PCR indices default: 0-7 (boot measurements)
- [x] Nonce inclusion (replay protection)
- [x] Timestamp auto-generated
- [x] JSON serialization con `sort_keys=True` (deterministic)
- [x] **SIMULATED**: Signature = SHA-256 di quote string
- [x] Return: Dict con `quote`, `signature`, `raw`

**Limitazione**:
- ❌ No real TPM `tpm2_quote` call
- ❌ Signature non crittografica (solo hash)

---

#### **4. ACM Normalization** ✅
```python
def normalize_to_acm(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
    acm_node = {
        "layer": "platform",  # or "hypervisor" depending on context
        "mode": "boot-time",
        "source": "tpm",
        "evidence": json.dumps(evidence),
        "signature": evidence.get("signature"),
        "timestamp": evidence.get("quote", {}).get("timestamp", self._get_timestamp()),
        "previous_hash": None
    }
    
    return acm_node
```

**Implementazione**:
- [x] Method signature corretta
- [x] Layer: `"platform"` (comment: context-dependent)
- [x] Mode: `"boot-time"`
- [x] Source: `"tpm"`
- [x] Evidence serialization con `json.dumps()`
- [x] Signature extraction from input
- [x] Timestamp fallback se missing
- [x] `previous_hash: None` (will be set by AMC chain)

---

#### **5. Helper Methods** ✅
```python
def _get_timestamp(self) -> str:
    import datetime
    return datetime.datetime.utcnow().isoformat() + "Z"

def _simulate_signature(self, data: str) -> str:
    signature = hashlib.sha256(data.encode()).hexdigest()
    return signature
```

**Implementazione**:
- [x] `_get_timestamp()`: ISO 8601 format con Z suffix
- [x] `_simulate_signature()`: SHA-256 hex digest
- [x] Private methods (underscore prefix)

---

#### **6. Main Test Function** ✅
```python
def main():
    adapter = TpmAdapter(use_simulator=True)
    
    # 1. Collect PCR values
    pcrs = adapter.collect_pcrs([0, 1, 2, 3, 4, 5, 6, 7])
    print(f"PCR values: {pcrs}")
    
    # 2. Collect quote
    nonce = "test_nonce_12345"
    quote = adapter.collect_quote(nonce=nonce)
    print(f"Quote: {json.dumps(quote, indent=2)}")
    
    # 3. Normalize to ACM
    acm_node = adapter.normalize_to_acm(quote)
    print(f"ACM Node: {json.dumps(acm_node, indent=2)}")
```

**Implementazione**:
- [x] Executable test (`if __name__ == "__main__"`)
- [x] 3-step workflow demo
- [x] JSON pretty-print con `indent=2`
- [x] Success message

---

### **Confidential Computing Adapter (`cc_adapter.py`)**

#### **1. Class Structure** ✅
```python
class CcAdapter:
    def __init__(self, platform: str = "snp"):
        self.platform = platform.lower()
        if self.platform not in ["snp", "tdx"]:
            raise ValueError("Platform must be 'snp' or 'tdx'")
```

**Implementazione**:
- [x] Constructor con platform selection
- [x] Input validation (only "snp" or "tdx")
- [x] Case-insensitive (`lower()`)
- [x] Raise `ValueError` per invalid platform

---

#### **2. Report Collection Dispatcher** ✅
```python
def collect_attestation_report(self, report_data: str = "") -> Dict[str, Any]:
    if self.platform == "snp":
        return self._collect_snp_report(report_data)
    elif self.platform == "tdx":
        return self._collect_tdx_report(report_data)
    else:
        raise ValueError(f"Unsupported platform: {self.platform}")
```

**Implementazione**:
- [x] Dispatch pattern basato su `self.platform`
- [x] `report_data` parameter (nonce/hash user-provided)
- [x] Error handling per unsupported platforms

---

#### **3. SEV-SNP Report Collection** ✅
```python
def _collect_snp_report(self, report_data: str) -> Dict[str, Any]:
    report = {
        "platform_info": "AMD EPYC 7xx3 Series",
        "platform_tcb": "0x0102030405060708",
        "report_data": report_data,
        "measurement": hashlib.sha256(b"simulated_vm_measurement").hexdigest(),
        "guest_policy": "0x30000",  # Default SNP policy
        "signature": self._simulate_signature("snp_report_data"),
        "timestamp": self._get_timestamp(),
        "certificate_chain": "simulated_vcek_chain"
    }
    return report
```

**Implementazione**:
- [x] Simulated AMD EPYC platform info
- [x] TCB version (hex format)
- [x] User `report_data` inclusion
- [x] VM measurement (SHA-256 simulated)
- [x] Guest policy (`0x30000` = default SEV-SNP)
- [x] Signature simulation
- [x] Timestamp auto-generated
- [x] VCEK certificate chain (placeholder)

**Limitazione**:
- ❌ No real `/dev/sev-guest` ioctl
- ❌ No real VCEK certificate chain retrieval

---

#### **4. TDX Report Collection** ✅
```python
def _collect_tdx_report(self, report_data: str) -> Dict[str, Any]:
    report = {
        "td_report": hashlib.sha256(b"simulated_td_report").hexdigest(),
        "td_quote": "simulated_td_quote",
        "report_data": report_data,
        "measurement": hashlib.sha256(b"simulated_td_measurement").hexdigest(),
        "mrseam": hashlib.sha256(b"simulated_mrseam").hexdigest(),
        "mrsignerseam": hashlib.sha256(b"simulated_mrsignerseam").hexdigest(),
        "timestamp": self._get_timestamp()
    }
    return report
```

**Implementazione**:
- [x] TD Report simulation (SHA-256 hash)
- [x] TD Quote placeholder
- [x] User `report_data` inclusion
- [x] TD measurement
- [x] MRSEAM (TDX module measurement)
- [x] MRSIGNERSEAM (TDX module signer)
- [x] Timestamp auto-generated

**Limitazione**:
- ❌ No real TDX TDCALL instruction
- ❌ No real TDX quote generation

---

#### **5. ACM Normalization** ✅
```python
def normalize_to_acm(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
    layer = "guest"
    source = "sev-snp" if self.platform == "snp" else "tdx"
    
    acm_node = {
        "layer": layer,
        "mode": "boot-time",
        "source": source,
        "evidence": json.dumps(evidence),
        "signature": evidence.get("signature"),
        "timestamp": evidence.get("timestamp", self._get_timestamp()),
        "previous_hash": None
    }
    
    return acm_node
```

**Implementazione**:
- [x] Layer: Always `"guest"` (CC è VM-level)
- [x] Source: Dynamic (`"sev-snp"` or `"tdx"`)
- [x] Mode: `"boot-time"`
- [x] Evidence JSON serialization
- [x] Signature extraction (only SNP has it)
- [x] Timestamp fallback

---

#### **6. Main Test Function** ✅
```python
def main():
    # Test SNP adapter
    snp_adapter = CcAdapter("snp")
    nonce = hashlib.sha256(b"test_nonce").hexdigest()
    snp_report = snp_adapter.collect_attestation_report(nonce)
    print(f"SNP Report: {json.dumps(snp_report, indent=2)}")
    snp_acm_node = snp_adapter.normalize_to_acm(snp_report)
    print(f"SNP ACM Node: {json.dumps(snp_acm_node, indent=2)}")
    
    # Test TDX adapter
    tdx_adapter = CcAdapter("tdx")
    tdx_report = tdx_adapter.collect_attestation_report(nonce)
    print(f"TDX Report: {json.dumps(tdx_report, indent=2)}")
    tdx_acm_node = tdx_adapter.normalize_to_acm(tdx_report)
    print(f"TDX ACM Node: {json.dumps(tdx_acm_node, indent=2)}")
```

**Implementazione**:
- [x] Both SNP and TDX tested
- [x] Shared nonce (SHA-256 hash)
- [x] Pretty-print JSON output
- [x] Success message

---

## ❌ **NON IMPLEMENTATO (Gap per Prototipo Completo)**

### **Critical Gaps - Rust Adapters**

#### **1. Real TPM Integration** 🔴 **CRITICO (Hardware)**
**Problema**: `TpmAdapter` fa solo JSON parsing, no hardware interaction

**Cosa serve**:
```rust
use tpm2_rs::*;  // Hypothetical TPM2 Rust bindings

impl TpmAdapter {
    fn collect_pcrs_from_hardware(&self, indices: &[u32]) -> Result<Vec<TpmPcr>, Error> {
        let mut tpm = Tpm::open("/dev/tpm0")?;
        
        let mut pcrs = Vec::new();
        for &index in indices {
            let value = tpm.pcr_read(index)?;
            pcrs.push(TpmPcr {
                index,
                value: hex::encode(value),
            });
        }
        
        Ok(pcrs)
    }
    
    fn collect_quote_from_hardware(&self, nonce: &[u8]) -> Result<TpmQuote, Error> {
        let mut tpm = Tpm::open("/dev/tpm0")?;
        
        // Load AIK (Attestation Identity Key)
        let aik = tpm.load_key(AIK_HANDLE)?;
        
        // Generate quote
        let quote = tpm.quote(aik, &[0, 1, 2, 3], nonce)?;
        
        // Sign quote
        let signature = tpm.sign(aik, &quote.digest)?;
        
        Ok(TpmQuote {
            pcrs: self.collect_pcrs_from_hardware(&[0, 1, 2, 3])?,
            signature: hex::encode(signature),
            quote: hex::encode(quote.raw),
        })
    }
}
```

**Codice da aggiungere**:
- [ ] Dependency: `tpm2-rs` o FFI bindings a `libtss2`
- [ ] `TpmAdapter::collect_pcrs_from_hardware()`
- [ ] `TpmAdapter::collect_quote_from_hardware()`
- [ ] Device handle management
- [ ] AIK key loading
- [ ] Error handling per TPM unavailable

**Impatto**: Adapter funziona solo con JSON pre-formattato, no real attestation

---

#### **2. SEV-SNP Report Fetching** 🔴 **CRITICO (Hardware)**
**Problema**: `SnpAdapter` fa solo JSON parsing

**Cosa serve**:
```rust
use std::fs::File;
use std::os::unix::io::AsRawFd;
use nix::ioctl_readwrite;

// SEV-SNP ioctl definitions
const SEV_GUEST_IOC_TYPE: u8 = b'S';
const SEV_SNP_GET_REPORT: u8 = 1;

#[repr(C)]
struct SnpReportRequest {
    user_data: [u8; 64],
    vmpl: u32,
    reserved: [u8; 28],
}

#[repr(C)]
struct SnpReportResponse {
    report: [u8; 1184],
    signature: [u8; 512],
}

ioctl_readwrite!(snp_get_report, SEV_GUEST_IOC_TYPE, SEV_SNP_GET_REPORT, SnpReportRequest);

impl SnpAdapter {
    fn collect_report_from_hardware(&self, user_data: &[u8; 64]) -> Result<SnpReport, Error> {
        let file = File::open("/dev/sev-guest")?;
        let fd = file.as_raw_fd();
        
        let mut request = SnpReportRequest {
            user_data: *user_data,
            vmpl: 0,
            reserved: [0; 28],
        };
        
        let mut response = SnpReportResponse {
            report: [0; 1184],
            signature: [0; 512],
        };
        
        unsafe {
            snp_get_report(fd, &mut request as *mut _ as *mut u8)?;
        }
        
        // Parse response
        Ok(SnpReport {
            data: hex::encode(&response.report),
            signature: hex::encode(&response.signature),
            platform_info: extract_platform_info(&response.report),
            policy: extract_policy(&response.report),
        })
    }
}
```

**Codice da aggiungere**:
- [ ] Dependency: `nix` per ioctl
- [ ] SEV-SNP ioctl definitions
- [ ] `/dev/sev-guest` device interaction
- [ ] Binary report parsing
- [ ] Certificate chain fetching (VCEK from AMD KDS)

**Impatto**: No real SEV-SNP attestation capability

---

#### **3. TDX Quote Generation** 🔴 **CRITICO (Hardware)**
**Problema**: `TdxAdapter` signature sempre `None`

**Cosa serve**:
```rust
use std::arch::x86_64::__cpuid;

// TDX TDCALL leaf numbers
const TDCALL_TDINFO: u64 = 1;
const TDCALL_TDREPORT: u64 = 4;

#[repr(C)]
struct TdReport {
    report_mac: [u8; 32],
    tee_tcb_info: [u8; 239],
    reserved: [u8; 17],
    td_info: [u8; 512],
}

impl TdxAdapter {
    fn collect_report_from_hardware(&self, report_data: &[u8; 64]) -> Result<TdxReport, Error> {
        // Check if running in TDX
        if !Self::is_tdx_enabled() {
            return Err("Not running in TDX environment".into());
        }
        
        // Allocate report buffer
        let mut report = TdReport::default();
        
        // Issue TDCALL to get TD Report
        unsafe {
            let ret = tdcall_tdreport(report_data.as_ptr(), &mut report as *mut _);
            if ret != 0 {
                return Err(format!("TDCALL failed: {}", ret).into());
            }
        }
        
        Ok(TdxReport {
            td_report: hex::encode(&report as *const _ as *const u8),
            td_quote: Self::generate_quote(&report)?,
        })
    }
    
    fn is_tdx_enabled() -> bool {
        // Check CPUID for TDX support
        unsafe {
            let cpuid = __cpuid(0x21);
            cpuid.eax == 0x746478 // "tdx" in hex
        }
    }
}
```

**Codice da aggiungere**:
- [ ] TDX TDCALL inline assembly
- [ ] CPUID check per TDX environment
- [ ] TD Report structure parsing
- [ ] Quote generation (via quoting enclave)
- [ ] Signature extraction from TD Quote

**Impatto**: TDX evidence **non verificabile** (no signature)

---

#### **4. Dynamic Layer Detection** 🟡 **MEDIUM (Flexibility)**
**Problema**: Layer sempre hardcoded (Platform/Guest)

**Cosa serve**:
```rust
impl TpmAdapter {
    pub fn normalize_to_acm_with_layer(
        &self,
        evidence: &str,
        layer: Layer,  // ← Dynamic parameter
    ) -> Result<AcmNode, String> {
        let quote: TpmQuote = serde_json::from_str(evidence)?;
        
        let node = AcmNode::new(
            layer,  // ← Use parameter instead of hardcoded
            Mode::BootTime,
            Source::Tpm,
            evidence.to_string(),
            Some(quote.signature),
            None,
        );
        
        Ok(node)
    }
}

// Usage in Attestation Manager:
let layer = detect_layer_from_context(&request.layer);
let node = adapter.normalize_to_acm_with_layer(&evidence, layer)?;
```

**Codice da aggiungere**:
- [ ] `normalize_to_acm_with_layer()` variant per tutti gli adapter
- [ ] Layer detection logic (vTPM → Platform, VM TPM → Hypervisor)
- [ ] Update Attestation Manager per usare nuovo metodo

**Impatto**: vTPM vs pTPM evidence non distinguibili

---

### **Critical Gaps - Python Adapters**

#### **5. Real TPM Commands (Python)** 🔴 **CRITICO (Hardware)**
**Problema**: `tpm_adapter.py` tutto simulato

**Cosa serve**:
```python
import subprocess
import json

class TpmAdapter:
    def collect_pcrs_from_hardware(self, pcr_indices: list) -> Dict[str, str]:
        """Collect real PCR values using tpm2_pcrread"""
        pcrs = {}
        
        for index in pcr_indices:
            try:
                # Call tpm2_pcrread command
                result = subprocess.run(
                    ["tpm2_pcrread", f"sha256:{index}", "-o", "-"],
                    capture_output=True,
                    text=True,
                    check=True
                )
                
                # Parse output: "sha256:\n  0: 0x1234..."
                value = self._parse_pcr_output(result.stdout, index)
                pcrs[str(index)] = value
                
            except subprocess.CalledProcessError as e:
                raise RuntimeError(f"Failed to read PCR {index}: {e}")
        
        return pcrs
    
    def collect_quote_from_hardware(self, pcr_indices: list, nonce: str) -> Dict[str, Any]:
        """Collect real TPM quote using tpm2_quote"""
        try:
            # Generate quote
            result = subprocess.run([
                "tpm2_quote",
                "-c", "0x81010001",  # AIK handle
                "-l", f"sha256:{','.join(map(str, pcr_indices))}",
                "-q", nonce,
                "-m", "/tmp/quote.msg",
                "-s", "/tmp/quote.sig",
                "-o", "/tmp/quote.pcr",
                "-g", "sha256"
            ], capture_output=True, text=True, check=True)
            
            # Read quote files
            with open("/tmp/quote.msg", "rb") as f:
                quote_msg = f.read()
            with open("/tmp/quote.sig", "rb") as f:
                quote_sig = f.read()
            
            return {
                "quote": {
                    "pcrs": self.collect_pcrs_from_hardware(pcr_indices),
                    "nonce": nonce,
                    "timestamp": self._get_timestamp()
                },
                "signature": quote_sig.hex(),
                "raw": quote_msg.hex()
            }
            
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"tpm2_quote failed: {e}")
```

**Codice da aggiungere**:
- [ ] `collect_pcrs_from_hardware()` con `tpm2_pcrread`
- [ ] `collect_quote_from_hardware()` con `tpm2_quote`
- [ ] Output parsing per `tpm2_*` tools
- [ ] Error handling per TPM unavailable
- [ ] Fallback a simulator se hardware missing

**Impatto**: Python adapter inutilizzabile con hardware TPM reale

---

#### **6. Real SEV-SNP Report (Python)** 🔴 **CRITICO (Hardware)**
**Problema**: `cc_adapter.py` tutto simulato

**Cosa serve**:
```python
import struct
import fcntl

class CcAdapter:
    SEV_GUEST_IOC_TYPE = ord('S')
    SEV_SNP_GET_REPORT = 1
    
    def _collect_snp_report_from_hardware(self, report_data: bytes) -> Dict[str, Any]:
        """Collect real SEV-SNP report via /dev/sev-guest ioctl"""
        try:
            with open("/dev/sev-guest", "rb") as device:
                # Prepare ioctl request
                request = struct.pack(
                    "64sI28s",  # user_data (64B), vmpl (4B), reserved (28B)
                    report_data[:64].ljust(64, b'\x00'),
                    0,  # VMPL 0
                    b'\x00' * 28
                )
                
                # Issue ioctl
                ioctl_cmd = (3 << 30) | (ord('S') << 8) | 1  # _IOWR
                response = fcntl.ioctl(device.fileno(), ioctl_cmd, request)
                
                # Parse response (1184B report + 512B signature)
                report_bytes = response[:1184]
                signature_bytes = response[1184:1184+512]
                
                return {
                    "platform_info": self._extract_platform_info(report_bytes),
                    "platform_tcb": self._extract_tcb(report_bytes),
                    "report_data": report_data.hex(),
                    "measurement": self._extract_measurement(report_bytes),
                    "guest_policy": self._extract_policy(report_bytes),
                    "signature": signature_bytes.hex(),
                    "timestamp": self._get_timestamp(),
                    "certificate_chain": self._fetch_vcek_cert()
                }
                
        except FileNotFoundError:
            raise RuntimeError("SEV-SNP device not found (/dev/sev-guest)")
        except OSError as e:
            raise RuntimeError(f"Failed to get SNP report: {e}")
    
    def _fetch_vcek_cert(self) -> str:
        """Fetch VCEK certificate from AMD KDS"""
        import requests
        
        # Read chip ID from SNP report
        chip_id = self._get_chip_id()
        
        # Fetch from AMD Key Distribution Service
        url = f"https://kdsintf.amd.com/vcek/v1/{chip_id}"
        response = requests.get(url)
        
        if response.status_code == 200:
            return response.text
        else:
            return "vcek_cert_unavailable"
```

**Codice da aggiungere**:
- [ ] `_collect_snp_report_from_hardware()` con ioctl
- [ ] Binary report parsing helpers
- [ ] VCEK certificate fetching da AMD KDS
- [ ] Struct unpacking per report fields
- [ ] Error handling per non-SEV environment

**Impatto**: Python adapter non funziona su SEV-SNP VM reale

---

#### **7. Real TDX Report (Python)** 🔴 **CRITICO (Hardware)**
**Problema**: `cc_adapter.py` TDX tutto simulato

**Cosa serve**:
```python
import ctypes
import os

class CcAdapter:
    def _collect_tdx_report_from_hardware(self, report_data: bytes) -> Dict[str, Any]:
        """Collect real TDX report via TDCALL"""
        try:
            # Check if running in TDX
            if not self._is_tdx_guest():
                raise RuntimeError("Not running in TDX guest")
            
            # Use TDX library (or inline assembly via ctypes)
            libtdx = ctypes.CDLL("libtdx.so")
            
            # Allocate report buffer
            report_buf = ctypes.create_string_buffer(1024)
            
            # Call TDX report generation
            ret = libtdx.tdx_get_report(
                ctypes.byref(report_buf),
                report_data[:64].ljust(64, b'\x00')
            )
            
            if ret != 0:
                raise RuntimeError(f"TDX report generation failed: {ret}")
            
            # Parse report
            return {
                "td_report": report_buf.raw.hex(),
                "td_quote": self._generate_td_quote(report_buf.raw),
                "report_data": report_data.hex(),
                "measurement": self._extract_mrtd(report_buf.raw),
                "mrseam": self._extract_mrseam(report_buf.raw),
                "mrsignerseam": self._extract_mrsignerseam(report_buf.raw),
                "timestamp": self._get_timestamp()
            }
            
        except OSError as e:
            raise RuntimeError(f"TDX library not found: {e}")
    
    def _is_tdx_guest(self) -> bool:
        """Check if running in TDX guest"""
        # Check for TDX-specific CPUID or device
        return os.path.exists("/dev/tdx-guest")
```

**Codice da aggiungere**:
- [ ] `_collect_tdx_report_from_hardware()` con TDCALL wrapper
- [ ] TDX library bindings (ctypes o FFI)
- [ ] Report buffer parsing
- [ ] Quote generation via quoting enclave
- [ ] TDX environment detection

**Impatto**: Python adapter non funziona su TDX VM reale

---

### **Non-Critical Gaps**

#### **8. ARM CCA Adapter** 🔵 **FUTURE**
**Current**: Nessun adapter per ARM Confidential Compute Architecture
**Missing**: CcaAdapter per ARM realm attestation

```rust
// Rust
pub struct CcaAdapter;

impl MralAdapter for CcaAdapter {
    fn normalize_to_acm(&self, evidence: &str) -> Result<AcmNode, String> {
        let token: CcaRealmToken = serde_json::from_str(evidence)?;
        
        let node = AcmNode::new(
            Layer::Guest,
            Mode::BootTime,
            Source::Cca,  // ← New Source variant
            evidence.to_string(),
            Some(token.signature),
            None,
        );
        
        Ok(node)
    }
}
```

```python
# Python
class CcAdapter:
    def _collect_cca_report(self, challenge: bytes) -> Dict[str, Any]:
        # Interface with ARM CCA PSA attestation API
        # Collect realm token + platform token
        pass
```

**Task**:
- [ ] Add `Source::Cca` enum variant in `amc.rs`
- [ ] `CcaAdapter` Rust implementation
- [ ] Python CCA adapter in `cc_adapter.py`
- [ ] ARM PSA attestation bindings
- [ ] Realm token parsing

---

#### **9. EVM Adapter** 🔵 **FUTURE**
**Current**: IMA adapter esiste, EVM no
**Missing**: Extended Verification Module support

```rust
pub struct EvmAdapter;

impl MralAdapter for EvmAdapter {
    fn normalize_to_acm(&self, evidence: &str) -> Result<AcmNode, String> {
        let measurement: EvmMeasurement = serde_json::from_str(evidence)?;
        
        let node = AcmNode::new(
            Layer::Runtime,
            Mode::Runtime,
            Source::Evm,  // ← Already exists
            evidence.to_string(),
            Some(measurement.signature),
            None,
        );
        
        Ok(node)
    }
}
```

**Task**:
- [ ] `EvmAdapter` Rust implementation
- [ ] EVM measurement structure
- [ ] Python EVM adapter
- [ ] Integration con IMA adapter (shared runtime layer)

---

#### **10. Comprehensive Unit Tests** 🟡
**Current**: 2 basic tests (TPM, SNP)
**Missing**: Full coverage

```rust
#[cfg(test)]
mod tests {
    // Existing tests ✅
    
    // Missing tests:
    #[test]
    fn test_tdx_adapter() { /* ... */ }
    
    #[test]
    fn test_ima_adapter() { /* ... */ }
    
    #[test]
    fn test_malformed_json() {
        let adapter = TpmAdapter::new();
        let result = adapter.normalize_to_acm("{invalid json}");
        assert!(result.is_err());
    }
    
    #[test]
    fn test_missing_signature() {
        let adapter = TpmAdapter::new();
        let quote_no_sig = r#"{"pcrs": [], "quote": "data"}"#;
        let result = adapter.normalize_to_acm(quote_no_sig);
        // Should handle gracefully
    }
    
    #[test]
    fn test_layer_preservation() {
        // Verify TpmAdapter uses Platform, SnpAdapter uses Guest
    }
}
```

**Task**:
- [ ] TDX adapter test
- [ ] IMA adapter test
- [ ] Error handling tests (malformed JSON, missing fields)
- [ ] Signature extraction tests
- [ ] Layer/source correctness tests

---

## 📊 **Checklist Riepilogativa**

### **Rust Adapters (`mral.rs`) - Functional Completeness**
| Component | Status | Priority |
|-----------|--------|----------|
| MralAdapter trait | ✅ Done | - |
| TpmAdapter (normalization) | ✅ Done | - |
| SnpAdapter (normalization) | ✅ Done | - |
| TdxAdapter (normalization) | ✅ Done | - |
| ImaAdapter (normalization) | ✅ Done | - |
| Evidence structs (5 types) | ✅ Done | - |
| JSON parsing | ✅ Done | - |
| Error handling (basic) | ✅ Done | - |
| Unit tests (2 tests) | ✅ Done | - |
| **Real TPM integration** | ❌ Missing | 🔴 Critical |
| **Real SEV-SNP integration** | ❌ Missing | 🔴 Critical |
| **Real TDX integration** | ❌ Missing | 🔴 Critical |
| **TDX signature extraction** | ❌ Missing | 🔴 Critical |
| **Dynamic layer detection** | ❌ Missing | 🟡 Medium |
| CCA adapter | ❌ Missing | 🔵 Future |
| EVM adapter | ❌ Missing | 🔵 Future |
| Comprehensive tests | ❌ Missing | 🟡 Optional |

### **Python Adapters - Functional Completeness**
| Component | Status | Priority |
|-----------|--------|----------|
| TpmAdapter class | ✅ Done | - |
| collect_pcrs() (simulated) | ✅ Done | - |
| collect_quote() (simulated) | ✅ Done | - |
| normalize_to_acm() (TPM) | ✅ Done | - |
| CcAdapter class | ✅ Done | - |
| SNP report collection (simulated) | ✅ Done | - |
| TDX report collection (simulated) | ✅ Done | - |
| normalize_to_acm() (CC) | ✅ Done | - |
| Main test functions | ✅ Done | - |
| Helper methods (timestamp, signature sim) | ✅ Done | - |
| **Real tpm2_tools integration** | ❌ Missing | 🔴 Critical |
| **Real /dev/sev-guest ioctl** | ❌ Missing | 🔴 Critical |
| **Real TDX TDCALL** | ❌ Missing | 🔴 Critical |
| **VCEK certificate fetching** | ❌ Missing | 🔴 Critical |
| CCA adapter (Python) | ❌ Missing | 🔵 Future |
| IMA adapter (Python) | ❌ Missing | 🔵 Future |

### **WP2 Deliverable Alignment**
| Requirement | Coverage |
|-------------|----------|
| **T2.1 Secure Bindings** | 40% (normalization OK, hardware interaction missing) |
| **D3 Design Analysis** | 80% (adapter architecture documented) |
| **D4 Implementation Report** | 60% (simulation working, hardware integration missing) |

---

## 🎯 **Priorità per Completamento Prototipo**

### **Weekend 7-8: Python Real Hardware Integration** (4 giorni)
1. **TPM real commands** (`tpm_adapter.py`)
   - `tpm2_pcrread` subprocess integration
   - `tpm2_quote` command wrapper
   - Output parsing
   - Error handling + fallback to simulator
   
2. **SEV-SNP real ioctl** (`cc_adapter.py`)
   - `/dev/sev-guest` device interaction
   - Binary report parsing
   - VCEK certificate fetching (AMD KDS)
   - Error handling + fallback to simulation

### **Weekend 9 (Optional): TDX + Rust Integration** (2 giorni)
3. **TDX real TDCALL** (`cc_adapter.py`)
   - TDX library bindings
   - TD Report generation
   - Quote extraction
   
4. **Rust hardware adapters** (`mral.rs`)
   - FFI bindings a Python adapters (or direct Rust implementation)
   - Update TdxAdapter per estrarre signature

---

## 💡 **Architectural Decisions Rationale**

### **Why Two Languages?**
- **Rust adapters**: Type-safe normalization, zero-copy parsing, production-ready
- **Python adapters**: Hardware prototyping, subprocess wrappers, rapid iteration

### **Why Trait Pattern?**
- **Extensibility**: New RoT → implement `MralAdapter` trait
- **Polymorphism**: `Box<dyn MralAdapter>` per runtime dispatch
- **Testing**: Mock adapters facilmente iniettabili

### **Why Simulated Evidence?**
- **Development**: No hardware dependency durante sviluppo
- **CI/CD**: Tests runnable senza TPM/TEE hardware
- **Portability**: Prototipo funziona su macOS/Windows

---

**In sintesi**:
- **Rust adapters**: ~70% implementato (normalization completa, hardware interaction missing)
- **Python adapters**: ~60% implementato (simulation completa, hardware commands missing)
- **Critical gap**: Hardware integration è **blocco totale** per production use
- **Priorità**: Weekend 7-8 risolvono TPM + SEV-SNP hardware interaction (sufficiente per paper demo)
