//! Validation logic for policy rules

use crate::policy::{ComplianceResult, ComplianceStatus, PolicyRule, PolicyViolation};
use chrono::{DateTime, Utc};
use regex::Regex;

/// Validate a node against a set of policy rules
pub fn validate_node(
    node_json: &serde_json::Value,
    rules: &[PolicyRule],
    policy_version: &str,
) -> ComplianceResult {
    let mut violations = Vec::new();
    
    for rule in rules {
        match rule.rule_type.as_str() {
            "field_presence" => {
                if let Some(violation) = validate_field_presence(node_json, rule) {
                    violations.push(violation);
                }
            }
            "field_pattern" => {
                if let Some(violation) = validate_field_pattern(node_json, rule) {
                    violations.push(violation);
                }
            }
            "timestamp_age" => {
                if let Some(violation) = validate_timestamp_age(node_json, rule) {
                    violations.push(violation);
                }
            }
            _ => {
                violations.push(PolicyViolation {
                    rule_type: rule.rule_type.clone(),
                    description: format!("Unknown rule type: {}", rule.rule_type),
                    severity: "medium".to_string(),
                    field_path: None,
                });
            }
        }
    }
    
    let status = if violations.is_empty() {
        ComplianceStatus::Compliant
    } else {
        ComplianceStatus::NonCompliant
    };
    
    ComplianceResult {
        status,
        violations,
        validated_at: Utc::now(),
        policy_version: policy_version.to_string(),
    }
}

/// Validate that required fields are present
fn validate_field_presence(
    node_json: &serde_json::Value,
    rule: &PolicyRule,
) -> Option<PolicyViolation> {
    let required_fields = rule.required_fields.as_ref()?;
    
    for field in required_fields {
        let value = get_field_by_path(node_json, field);
        
        if value.is_none() || value == Some(&serde_json::Value::Null) {
            return Some(PolicyViolation {
                rule_type: "field_presence".to_string(),
                description: rule.error_message.clone().unwrap_or_else(|| {
                    format!("Required field '{}' is missing or null", field)
                }),
                severity: "high".to_string(),
                field_path: Some(field.clone()),
            });
        }
        
        // If field_path is specified, check nested structure
        if let Some(ref path) = rule.field_path {
            if let Some(parent) = value {
                let nested = get_field_by_path(parent, path);
                if nested.is_none() || nested == Some(&serde_json::Value::Null) {
                    return Some(PolicyViolation {
                        rule_type: "field_presence".to_string(),
                        description: rule.error_message.clone().unwrap_or_else(|| {
                            format!("Required nested field '{}' in '{}' is missing", path, field)
                        }),
                        severity: "high".to_string(),
                        field_path: Some(format!("{}.{}", field, path)),
                    });
                }
            }
        }
    }
    
    None
}

/// Validate that a field matches a regex pattern
fn validate_field_pattern(
    node_json: &serde_json::Value,
    rule: &PolicyRule,
) -> Option<PolicyViolation> {
    let field_path = rule.field_path.as_ref()?;
    let pattern_str = rule.pattern.as_ref()?;
    let must_match = rule.must_match.unwrap_or(true);
    
    let field_value = get_field_by_path(node_json, field_path)?;
    let field_str = field_value.as_str()?;
    
    let regex = match Regex::new(pattern_str) {
        Ok(r) => r,
        Err(e) => {
            return Some(PolicyViolation {
                rule_type: "field_pattern".to_string(),
                description: format!("Invalid regex pattern '{}': {}", pattern_str, e),
                severity: "medium".to_string(),
                field_path: Some(field_path.clone()),
            });
        }
    };
    
    let matches = regex.is_match(field_str);
    
    if must_match && !matches {
        return Some(PolicyViolation {
            rule_type: "field_pattern".to_string(),
            description: rule.error_message.clone().unwrap_or_else(|| {
                format!("Field '{}' does not match required pattern '{}'", field_path, pattern_str)
            }),
            severity: "high".to_string(),
            field_path: Some(field_path.clone()),
        });
    }
    
    if !must_match && matches {
        return Some(PolicyViolation {
            rule_type: "field_pattern".to_string(),
            description: rule.error_message.clone().unwrap_or_else(|| {
                format!("Field '{}' matches forbidden pattern '{}'", field_path, pattern_str)
            }),
            severity: "critical".to_string(),
            field_path: Some(field_path.clone()),
        });
    }
    
    None
}

/// Validate timestamp freshness
fn validate_timestamp_age(
    node_json: &serde_json::Value,
    rule: &PolicyRule,
) -> Option<PolicyViolation> {
    let max_age = rule.max_age_seconds?;
    
    let timestamp_str = node_json
        .get("timestamp")
        .and_then(|v| v.as_str())?;
    
    let timestamp = match DateTime::parse_from_rfc3339(timestamp_str) {
        Ok(dt) => dt.with_timezone(&Utc),
        Err(e) => {
            return Some(PolicyViolation {
                rule_type: "timestamp_age".to_string(),
                description: format!("Invalid timestamp format: {}", e),
                severity: "high".to_string(),
                field_path: Some("timestamp".to_string()),
            });
        }
    };
    
    let now = Utc::now();
    let age = now.signed_duration_since(timestamp);
    
    if age.num_seconds() > max_age as i64 {
        return Some(PolicyViolation {
            rule_type: "timestamp_age".to_string(),
            description: rule.error_message.clone().unwrap_or_else(|| {
                format!(
                    "Timestamp is too old: {} seconds (max: {})",
                    age.num_seconds(),
                    max_age
                )
            }),
            severity: "high".to_string(),
            field_path: Some("timestamp".to_string()),
        });
    }
    
    None
}

/// Get a field from JSON using dot notation path
fn get_field_by_path<'a>(
    json: &'a serde_json::Value,
    path: &str,
) -> Option<&'a serde_json::Value> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = json;
    
    for part in parts {
        // Check if it's an array index
        if let Ok(index) = part.parse::<usize>() {
            current = current.get(index)?;
        } else {
            current = current.get(part)?;
        }
    }
    
    Some(current)
}