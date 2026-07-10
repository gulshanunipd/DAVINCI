//! Multi-RoT Abstraction Layer (MRAL) implementation
//! 
//! This module provides adapters for different Root of Trust (RoT) sources
//! and normalizes their outputs to the AMC format.

use serde::{Deserialize, Serialize};
use crate::amc::{AcmNode, Layer, Mode, Source};
use crate::crypto;
use openssl::pkey::{PKey, Public};

/// MRAL `Auth` predicate (D3 Eq. 5): verify that the normalized evidence carries
/// an authentic Root-of-Trust signature over its measurement/timestamp `(µ, ts)`.
///
/// The evidence envelope produced by each source carries:
///   - `measurement`: the RoT measurement digest µ (hex SHA-256)
///   - `ts`: the hardware timestamp (unix seconds)
///   - `rot_sig`: hex(DER) ECDSA-P256 signature by sk_r over the bytes `µ|ts`
///
/// Only evidence with `Auth == 1` may be admitted to E_sid; this is the
/// security gate that D2/D3 place before Transform and Attest.
pub fn verify_rot_auth(
    evidence: &serde_json::Value,
    rot_pub: &PKey<Public>,
) -> Result<(), String> {
    let measurement = evidence
        .get("measurement")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "evidence missing 'measurement' (µ)".to_string())?;
    let ts = evidence
        .get("ts")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| "evidence missing integer 'ts'".to_string())?;
    let rot_sig = evidence
        .get("rot_sig")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "evidence missing 'rot_sig' (RoT signature)".to_string())?;

    // Canonical signed message: exactly what each source signs.
    let msg = format!("{}|{}", measurement, ts);
    if crypto::verify_hex(rot_pub, msg.as_bytes(), rot_sig) {
        Ok(())
    } else {
        Err("RoT signature invalid — evidence not authentic (Auth = 0)".to_string())
    }
}

/// TPM Quote structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmQuote {
    /// PCR values
    pub pcrs: Vec<TpmPcr>,
    
    /// Quote signature
    pub signature: String,
    
    /// Quote data
    pub quote: String,
}

/// TPM PCR structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmPcr {
    /// PCR index
    pub index: u32,
    
    /// PCR value
    pub value: String,
}

/// SEV-SNP Report structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnpReport {
    /// Report data
    pub data: String,
    
    /// Signature
    pub signature: String,
    
    /// Platform information
    pub platform_info: String,
    
    /// Guest policy
    pub policy: String,
}

/// TDX Report structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TdxReport {
    /// TD Report data
    pub td_report: String,
    
    /// TD Quote
    pub td_quote: String,
}

/// IMA Measurement structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImaMeasurement {
    /// File path
    pub path: String,
    
    /// File hash
    pub hash: String,
    
    /// Template hash
    pub template_hash: String,
    
    /// Timestamp
    pub timestamp: String,
}

/// MRAL Adapter trait
pub trait MralAdapter {
    /// Normalize evidence to ACM node format
    fn normalize_to_acm(&self, evidence: &str) -> Result<AcmNode, String>;
}

/// TPM Adapter
pub struct TpmAdapter;

impl TpmAdapter {
    pub fn new() -> Self {
        TpmAdapter
    }
}

impl MralAdapter for TpmAdapter {
    fn normalize_to_acm(&self, evidence: &str) -> Result<AcmNode, String> {
        // Parse TPM evidence (already in EAT ACM Node format from Python adapter)
        let node: AcmNode = serde_json::from_str(evidence)
            .map_err(|e| format!("Failed to parse TPM EAT evidence: {}", e))?;
        
        Ok(node)
    }
}

/// SEV-SNP Adapter
pub struct SnpAdapter;

impl SnpAdapter {
    pub fn new() -> Self {
        SnpAdapter
    }
}

impl MralAdapter for SnpAdapter {
    fn normalize_to_acm(&self, evidence: &str) -> Result<AcmNode, String> {
        // Parse SEV-SNP evidence
        let node: AcmNode = serde_json::from_str(evidence)
            .map_err(|e| format!("Failed to parse SEV-SNP EAT evidence: {}", e))?;
        
        Ok(node)
    }
}

/// TDX Adapter
pub struct TdxAdapter;

impl TdxAdapter {
    pub fn new() -> Self {
        TdxAdapter
    }
}

impl MralAdapter for TdxAdapter {
    fn normalize_to_acm(&self, evidence: &str) -> Result<AcmNode, String> {
        // Parse TDX evidence
        let node: AcmNode = serde_json::from_str(evidence)
            .map_err(|e| format!("Failed to parse TDX EAT evidence: {}", e))?;
        
        Ok(node)
    }
}

/// IMA Adapter
pub struct ImaAdapter;

impl ImaAdapter {
    pub fn new() -> Self {
        ImaAdapter
    }
}

impl MralAdapter for ImaAdapter {
    fn normalize_to_acm(&self, evidence: &str) -> Result<AcmNode, String> {
        // Parse IMA evidence
        let node: AcmNode = serde_json::from_str(evidence)
            .map_err(|e| format!("Failed to parse IMA EAT evidence: {}", e))?;
        
        Ok(node)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_tpm_adapter() {
        let adapter = TpmAdapter::new();
        
        let sample_quote = r#"{
            "pcrs": [
                {"index": 0, "value": "abc123"},
                {"index": 1, "value": "def456"}
            ],
            "signature": "quote_signature",
            "quote": "quote_data"
        }"#;
        
        let result = adapter.normalize_to_acm(sample_quote);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_snp_adapter() {
        let adapter = SnpAdapter::new();
        
        let sample_report = r#"{
            "data": "report_data",
            "signature": "report_signature",
            "platform_info": "platform_info",
            "policy": "guest_policy"
        }"#;
        
        let result = adapter.normalize_to_acm(sample_report);
        assert!(result.is_ok());
    }
}