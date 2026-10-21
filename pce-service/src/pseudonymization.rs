//! Pseudonymization module for stable identifier protection

use std::collections::HashMap;
use openssl::hash::{hash, MessageDigest};
use serde::{Deserialize, Serialize};

/// Session-scoped pseudonym manager
#[derive(Debug, Clone)]
pub struct PseudonymManager {
    session_id: String,
    session_key: Vec<u8>,
    mappings: HashMap<String, String>,
}

impl PseudonymManager {
    pub fn new(session_id: String) -> Self {
        let session_key = Self::derive_session_key(&session_id);
        
        PseudonymManager {
            session_id,
            session_key,
            mappings: HashMap::new(),
        }
    }
    
    fn derive_session_key(session_id: &str) -> Vec<u8> {
        hash(MessageDigest::sha256(), session_id.as_bytes())
            .unwrap()
            .to_vec()
    }
    
    /// Generate a session-scoped pseudonym for a stable identifier
    pub fn pseudonymize(&mut self, field_name: &str, real_value: &str) -> String {
        let mapping_key = format!("{}:{}", field_name, real_value);
        
        if let Some(pseudonym) = self.mappings.get(&mapping_key) {
            return pseudonym.clone();
        }
        
        let mut data_to_hash = self.session_key.clone();
        data_to_hash.extend_from_slice(field_name.as_bytes());
        data_to_hash.extend_from_slice(real_value.as_bytes());
        
        let pseudonym_bytes = hash(MessageDigest::sha256(), &data_to_hash).unwrap();
        let pseudonym = format!("psn_{}", hex::encode(&pseudonym_bytes[..16]));
        
        self.mappings.insert(mapping_key, pseudonym.clone());
        
        pseudonym
    }
    
    /// Detect potential privacy risks in evidence (source-aware)
    pub fn detect_risks(&self, evidence: &serde_json::Value, source: &str) -> Vec<PrivacyRisk> {
        let mut risks = Vec::new();
        
        // Stable identifier fields per source
        let stable_fields: Vec<&str> = match source {
            "Tpm" => vec!["aik_cert", "ek_cert", "qualified_signer"],
            "Tdx" => vec!["mrseam", "mrtd", "mrconfigid", "mrowner", "mrownerconfig"],
            "SevSnp" => vec!["vcek_cert", "chip_id", "id_key_digest", "author_key_digest"],
            "Cca" => vec!["instance_id", "realm_public_key", "signer_id"],
            "OpTee" => vec!["attestation_key_fpr"],
            _ => vec![],
        };
        
        for field in &stable_fields {
            if let Some(value) = evidence.get(field) {
                if let Some(val_str) = value.as_str() {
                    if val_str.len() > 10 {
                        risks.push(PrivacyRisk {
                            risk_type: "stable_identifier".to_string(),
                            field: field.to_string(),
                            severity: "high".to_string(),
                        });
                    }
                }
            }
        }
        
        // Fingerprinting fields per source
        let fingerprint_fields: Vec<&str> = match source {
            "Tpm" => vec!["firmware_version", "platform_info"],
            "Tdx" => vec!["tee_tcb_svn", "reportdata"],
            "SevSnp" => vec!["host_data", "current_tcb", "reported_tcb", "committed_tcb"],
            "Cca" => vec!["hw_version", "arm_platform_config"],
            _ => vec![],
        };
        
        for field in &fingerprint_fields {
            if evidence.get(field).is_some() {
                risks.push(PrivacyRisk {
                    risk_type: "fingerprinting".to_string(),
                    field: field.to_string(),
                    severity: "medium".to_string(),
                });
            }
        }
        
        // Check for large datasets (generic, applies to all sources)
        if let Some(ima_log) = evidence.get("ima_log") {
            if ima_log.is_array() {
                if let Some(arr) = ima_log.as_array() {
                    if arr.len() > 100 {
                        risks.push(PrivacyRisk {
                            risk_type: "large_dataset".to_string(),
                            field: "ima_log".to_string(),
                            severity: "medium".to_string(),
                        });
                    }
                }
            }
        }
        
        risks
    }
}

/// Privacy risk detected in attestation data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyRisk {
    pub risk_type: String,
    pub field: String,
    pub severity: String,
}