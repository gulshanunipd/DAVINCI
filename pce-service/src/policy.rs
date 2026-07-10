//! Policy definitions and structures

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// Top-level policy structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Policy version
    pub version: String,
    
    /// Map of policy ID to component policy
    pub policies: HashMap<String, ComponentPolicy>,
}

/// Policy for a specific component type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentPolicy {
    /// Criteria for when this policy applies
    pub applies_to: AppliesTo,
    
    /// List of validation rules
    pub rules: Vec<PolicyRule>,
}

/// Criteria for policy applicability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppliesTo {
    /// Layer (Platform, Hypervisor, Guest, Runtime)
    pub layer: Option<String>,
    
    /// Mode (BootTime, Runtime, Policy)
    pub mode: Option<String>,
    
    /// Source (Tpm, SevSnp, Tdx, Ima, Evm)
    pub source: Option<String>,
}

/// Individual validation rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Type of rule (field_presence, field_pattern, timestamp_age, etc.)
    pub rule_type: String,
    
    /// List of required fields (for field_presence)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_fields: Option<Vec<String>>,
    
    /// Field path to validate (dot notation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field_path: Option<String>,
    
    /// Regex pattern (for field_pattern)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    
    /// Whether pattern must match (true) or must not match (false)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub must_match: Option<bool>,
    
    /// Maximum age in seconds (for timestamp_age)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_age_seconds: Option<u64>,
    
    /// Custom error message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

/// Result of compliance validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceResult {
    /// Overall compliance status
    pub status: ComplianceStatus,
    
    /// List of policy violations
    pub violations: Vec<PolicyViolation>,
    
    /// Timestamp of validation
    pub validated_at: DateTime<Utc>,
    
    /// Policy version used
    pub policy_version: String,
}

/// Compliance status enum
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ComplianceStatus {
    Compliant,
    NonCompliant,
    Unknown,
}

/// Individual policy violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolation {
    /// Rule that was violated
    pub rule_type: String,
    
    /// Description of the violation
    pub description: String,
    
    /// Severity (critical, high, medium, low)
    pub severity: String,
    
    /// Field path that caused the violation
    pub field_path: Option<String>,
}

impl Policy {
    /// Find ALL applicable policies (specific + universal) for a given node
    pub fn find_applicable_policies(&self, node: &serde_json::Value) -> Vec<&ComponentPolicy> {
        let layer = node.get("layer").and_then(|v| v.as_str());
        let mode = node.get("mode").and_then(|v| v.as_str());
        let source = node.get("source").and_then(|v| v.as_str());
        
        let mut applicable = Vec::new();
        
        // PASS 1: Trova UNA policy specifica che matcha
        for policy in self.policies.values() {
            if policy.applies_to.is_specific() && policy.applies_to.matches(layer, mode, source) {
                applicable.push(policy);
                break; // Solo la prima policy specifica
            }
        }
        
        // PASS 2: Aggiungi TUTTE le policy universali (cross-cutting concerns)
        for policy in self.policies.values() {
            if policy.applies_to.is_universal() {
                applicable.push(policy);
            }
        }
        
        applicable
    }
    
}

impl AppliesTo {
    /// Check if this is a specific policy (at least one field defined)
    fn is_specific(&self) -> bool {
        self.layer.is_some() || self.mode.is_some() || self.source.is_some()
    }
    
    /// Check if this is a universal policy (all fields are None)
    fn is_universal(&self) -> bool {
        self.layer.is_none() && self.mode.is_none() && self.source.is_none()
    }
    
    /// Check if this policy applies to the given attributes
    fn matches(&self, layer: Option<&str>, mode: Option<&str>, source: Option<&str>) -> bool {
        let layer_matches = self.layer.as_ref().map_or(true, |l| Some(l.as_str()) == layer);
        let mode_matches = self.mode.as_ref().map_or(true, |m| Some(m.as_str()) == mode);
        let source_matches = self.source.as_ref().map_or(true, |s| Some(s.as_str()) == source);
        
        layer_matches && mode_matches && source_matches
    }
}