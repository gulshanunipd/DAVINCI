//! Selective disclosure and field redaction module.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;

/// Defines a policy for what to disclose in a given piece of evidence.
#[derive(Debug, Clone)]
pub struct DisclosurePolicy {
    /// Fields that are essential for cryptographic verification and must be retained.
    pub required_for_verification: HashSet<String>,
    
    /// Fields that can be replaced with a cryptographic hash (e.g., for large logs).
    pub aggregatable_fields: HashSet<String>,
    
    /// Fields that are sensitive or unnecessary and should be removed completely.
    pub redact_fields: HashSet<String>,
}

impl DisclosurePolicy {
    /// Creates a default disclosure policy for TPM-based evidence.
    pub fn for_tpm() -> Self {
        let mut required = HashSet::new();
        required.insert("pcr_selection".to_string());
        required.insert("pcr_digest".to_string());
        required.insert("qualified_signer".to_string());
        required.insert("extra_data".to_string());
        required.insert("clock_info".to_string());
        required.insert("pcrs".to_string());

        let mut aggregatable = HashSet::new();
        aggregatable.insert("ima_log".to_string());
        aggregatable.insert("event_log".to_string());
        // The raw TPMS_ATTEST embeds the AK qualified name; exporting it would
        // undo the pseudonymization of `qualified_signer`.
        aggregatable.insert("quote".to_string());
        aggregatable.insert("firmware_version".to_string());
        aggregatable.insert("platform_info".to_string());
        
        // Sensitive, verification-irrelevant fields removed entirely (suppress).
        let mut redact = HashSet::new();
        for f in ["hostname", "ip_address", "serial_number", "operator_note"] {
            redact.insert(f.to_string());
        }

        DisclosurePolicy {
            required_for_verification: required,
            aggregatable_fields: aggregatable,
            redact_fields: redact,
        }
    }
    
    /// Creates a default disclosure policy for Intel TDX-based evidence.
    pub fn for_tdx() -> Self {
        let mut required = HashSet::new();
        required.insert("mrtd".to_string());
        required.insert("rtmr0".to_string());
        required.insert("rtmr1".to_string());
        required.insert("rtmr2".to_string());
        required.insert("rtmr3".to_string());
        required.insert("attributes".to_string());
        
        let mut aggregatable = HashSet::new();
        aggregatable.insert("tee_tcb_svn".to_string());
        aggregatable.insert("reportdata".to_string());
        aggregatable.insert("mrconfigid".to_string());
        aggregatable.insert("mrowner".to_string());
        aggregatable.insert("mrownerconfig".to_string());
        
        // Sensitive, verification-irrelevant fields removed entirely (suppress).
        let mut redact = HashSet::new();
        for f in ["hostname", "ip_address", "serial_number", "operator_note"] {
            redact.insert(f.to_string());
        }

        DisclosurePolicy {
            required_for_verification: required,
            aggregatable_fields: aggregatable,
            redact_fields: redact,
        }
    }
    
    /// Creates a default disclosure policy for AMD SEV-SNP-based evidence.
    pub fn for_snp() -> Self {
        let mut required = HashSet::new();
        required.insert("version".to_string());
        required.insert("policy".to_string());
        required.insert("measurement".to_string());
        required.insert("family_id".to_string());
        required.insert("image_id".to_string());
        required.insert("vmpl".to_string());
        
        let mut aggregatable = HashSet::new();
        aggregatable.insert("current_tcb".to_string());
        aggregatable.insert("reported_tcb".to_string());
        aggregatable.insert("committed_tcb".to_string());
        aggregatable.insert("report_data".to_string());
        aggregatable.insert("host_data".to_string());
        aggregatable.insert("chip_id".to_string());
        aggregatable.insert("report_id".to_string());
        aggregatable.insert("report_id_ma".to_string());
        
        // Sensitive, verification-irrelevant fields removed entirely (suppress).
        let mut redact = HashSet::new();
        for f in ["hostname", "ip_address", "serial_number", "operator_note"] {
            redact.insert(f.to_string());
        }

        DisclosurePolicy {
            required_for_verification: required,
            aggregatable_fields: aggregatable,
            redact_fields: redact,
        }
    }
    
    /// Creates a default disclosure policy for ARM CCA-based evidence.
    pub fn for_cca() -> Self {
        let mut required = HashSet::new();
        // Platform token essentials
        required.insert("instance_id".to_string());
        required.insert("nonce".to_string());
        required.insert("eat_profile".to_string());
        required.insert("hw_model".to_string());
        // Realm token essentials
        required.insert("realm_measurement".to_string());
        required.insert("realm_hash_alg_id".to_string());
        required.insert("realm_public_key".to_string());
        
        let mut aggregatable = HashSet::new();
        aggregatable.insert("software_components".to_string());
        aggregatable.insert("hw_version".to_string());
        aggregatable.insert("arm_platform_config".to_string());
        aggregatable.insert("realm_public_key_hash_alg_id".to_string());
        
        // Sensitive, verification-irrelevant fields removed entirely (suppress).
        let mut redact = HashSet::new();
        for f in ["hostname", "ip_address", "serial_number", "operator_note"] {
            redact.insert(f.to_string());
        }

        DisclosurePolicy {
            required_for_verification: required,
            aggregatable_fields: aggregatable,
            redact_fields: redact,
        }
    }
    
    /// Creates a default disclosure policy for OP-TEE attestation PTA evidence.
    pub fn for_optee() -> Self {
        let mut required = HashSet::new();
        for f in ["nonce", "tee_core_hash", "ta_uuid", "ta_memory_hash", "ta_shdr_digest"] {
            required.insert(f.to_string());
        }

        // Signatures were verified by the MRAL; the verifier only needs the
        // measurements, so the bulky signatures are replaced by their hash.
        let mut aggregatable = HashSet::new();
        aggregatable.insert("signature".to_string());
        aggregatable.insert("shdr_signature".to_string());

        // Sensitive, verification-irrelevant fields removed entirely (suppress).
        let mut redact = HashSet::new();
        for f in ["hostname", "ip_address", "serial_number", "operator_note"] {
            redact.insert(f.to_string());
        }

        DisclosurePolicy {
            required_for_verification: required,
            aggregatable_fields: aggregatable,
            redact_fields: redact,
        }
    }

    /// Applies the disclosure policy to a JSON value representing the evidence.
    /// It modifies the value in place and returns a manifest of the changes made.
    pub fn apply(&self, evidence: &mut Value) -> DisclosureManifest {
        let mut manifest = DisclosureManifest::new();
        
        // Note: The order of operations matters. Redact first, then aggregate.
        
        // Redact sensitive fields
        for field_path in &self.redact_fields {
            if self.remove_field(evidence, field_path) {
                manifest.redacted_fields.push(field_path.clone());
            }
        }
        
        // Aggregate large or detailed fields
        for field_path in &self.aggregatable_fields {
            if let Some(aggregated_hash) = self.aggregate_field(evidence, field_path) {
                manifest.aggregated_fields.push((field_path.clone(), aggregated_hash));
            }
        }
        
        // Track which required fields were actually retained
        for field_path in &self.required_for_verification {
            if self.field_exists(evidence, field_path) {
                manifest.retained_fields.push(field_path.clone());
            }
        }
        
        manifest
    }
    
    // --- Helper functions for manipulating JSON Value ---
    
    fn remove_field(&self, value: &mut Value, path: &str) -> bool {
        let mut parts: Vec<&str> = path.split('.').collect();
        let last_part = parts.pop().unwrap_or("");
        
        let mut current = value;
        for part in parts {
            if let Some(c) = current.get_mut(part) {
                current = c;
            } else {
                return false; // Path does not exist
            }
        }
        
        if let Value::Object(map) = current {
            map.remove(last_part).is_some()
        } else {
            false
        }
    }
    
    fn aggregate_field(&self, value: &mut Value, path: &str) -> Option<String> {
        if let Some(field_value) = self.get_field(value, path) {
            let data_to_hash = serde_json::to_string(field_value).ok()?;
            let hash_bytes = openssl::hash::hash(
                openssl::hash::MessageDigest::sha256(),
                data_to_hash.as_bytes()
            ).ok()?;
            
            let hash_hex = hex::encode(hash_bytes);
            let new_value = Value::String(format!("aggregated_hash:{}", hash_hex));
            
            self.set_field(value, path, new_value);
            
            Some(hash_hex)
        } else {
            None
        }
    }
    
    fn field_exists(&self, value: &Value, path: &str) -> bool {
        self.get_field(value, path).is_some()
    }
    
    fn get_field<'a>(&self, value: &'a Value, path: &str) -> Option<&'a Value> {
        let parts: Vec<&str> = path.split('.').collect();
        let mut current = value;
        
        for part in parts {
            current = current.get(part)?;
        }
        
        Some(current)
    }
    
    fn set_field(&self, value: &mut Value, path: &str, new_value: Value) {
        let mut parts: Vec<&str> = path.split('.').collect();
        let last_part = parts.pop().unwrap_or("");
        
        let mut current = value;
        for part in parts {
            if current.get(part).is_none() {
                // Path doesn't exist, cannot set
                return;
            }
            current = current.get_mut(part).unwrap();
        }
        
        if let Value::Object(map) = current {
            map.insert(last_part.to_string(), new_value);
        }
    }
}

/// A manifest describing the privacy transformations applied to a piece of evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisclosureManifest {
    /// List of fields that were completely removed.
    pub redacted_fields: Vec<String>,
    /// List of fields that were replaced by a hash, and the resulting hash.
    pub aggregated_fields: Vec<(String, String)>,
    /// List of critical fields that were kept for verification.
    pub retained_fields: Vec<String>,
}

impl DisclosureManifest {
    pub fn new() -> Self {
        DisclosureManifest {
            redacted_fields: Vec::new(),
            aggregated_fields: Vec::new(),
            retained_fields: Vec::new(),
        }
    }
}