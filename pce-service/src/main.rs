//! Privacy Control Engine (PCE) Service
//! 
//! HTTP service that applies privacy transformations to attestation evidence

use warp::Filter;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::collections::HashMap;
use sha2::{Sha256, Digest};

use pce_service::{Policy, ComplianceResult, validate_node};
use pce_service::pseudonymization::{PseudonymManager, PrivacyRisk};
use pce_service::disclosure::{DisclosurePolicy, DisclosureManifest};
use pce_service::{PseudonymStore, PostgresPseudonymStore, InMemoryPseudonymStore, PseudonymMapping};
use pce_service::crypto::{extract_public_key_from_cert, is_pem_certificate};
use chrono::Utc;

/// Request for privacy transformation
#[derive(Debug, Deserialize)]
struct TransformRequest {
    session_id: String,
    source: String,
    evidence: String,
}

/// Response for privacy transformation
#[derive(Debug, Serialize)]
struct TransformResponse {
    transformed_evidence: String,
    manifest: DisclosureManifest,
    risks: Vec<PrivacyRisk>,
}

/// Request for node validation
#[derive(Debug, Deserialize)]
struct ValidateNodeRequest {
    node: serde_json::Value,
}

/// Response for validation
#[derive(Debug, Serialize)]
struct ValidateNodeResponse {
    result: ComplianceResult,
}

/// Request for pseudonym resolution
#[derive(Debug, Deserialize)]
struct ResolvePseudonymRequest {
    session_id: String,
    pseudonym: String,
}

/// Response for pseudonym resolution
#[derive(Debug, Serialize)]
struct ResolvePseudonymResponse {
    pseudonym: String,
    field_name: String,
    public_key_pem: Option<String>,
    key_type: Option<String>,
    source: Option<String>,
}

/// Application state
#[derive(Clone)]
struct PceState {
    policies: Arc<HashMap<String, Policy>>,
    store: Arc<dyn PseudonymStore>,
}

#[tokio::main]
async fn main() {
    println!("🔒 Starting Privacy Control Engine on port 3032...");
    
    // Initialize persistence store
    let store: Arc<dyn PseudonymStore> = if let Ok(db_url) = std::env::var("DATABASE_URL") {
        println!("🗄️  Connecting to PostgreSQL...");
        match PostgresPseudonymStore::from_url(&db_url).await {
            Ok(pg_store) => {
                println!("   ✅ PostgreSQL connected");
                // Run migrations
                if let Err(e) = pg_store.migrate().await {
                    println!("   ⚠️  Migration warning: {}", e);
                }
                Arc::new(pg_store)
            }
            Err(e) => {
                println!("   ⚠️  PostgreSQL failed ({}), falling back to in-memory store", e);
                Arc::new(InMemoryPseudonymStore::new())
            }
        }
    } else {
        println!("🗄️  Using in-memory store (no DATABASE_URL set)");
        Arc::new(InMemoryPseudonymStore::new())
    };
    
    let policies = load_policies("policies/default_policies.json")
        .unwrap_or_else(|e| {
            println!("⚠️  Policy file not found: {}. Validation endpoint will be limited.", e);
            HashMap::new()
        });
    
    let state = PceState {
        policies: Arc::new(policies),
        store,
    };
    
    println!("✅ Loaded {} policy sets", state.policies.len());
    
    let state_filter = warp::any().map(move || state.clone());
    
    let transform_route = warp::post()
        .and(warp::path("privacy"))
        .and(warp::path("transform"))
        .and(warp::path::end())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(handle_transform);
    
    let validate_route = warp::post()
        .and(warp::path("validate"))
        .and(warp::path("node"))
        .and(warp::path::end())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(handle_validate);
    
    let resolve_route = warp::post()
        .and(warp::path("resolve"))
        .and(warp::path("pseudonym"))
        .and(warp::path::end())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(handle_resolve);
    
    let health_route = warp::get()
        .and(warp::path("health"))
        .and(warp::path::end())
        .and(state_filter.clone())
        .and_then(handle_health);
    
    let routes = transform_route
        .or(validate_route)
        .or(resolve_route)
        .or(health_route);
    
    println!("🚀 PCE ready on http://localhost:3032");
    println!("   POST /privacy/transform  - Privacy transformations (Tpm, Tdx, SevSnp, Cca)");
    println!("   POST /validate/node      - Policy validation");
    println!("   POST /resolve/pseudonym  - Resolve pseudonym to public key");
    println!("   GET  /health             - Health check");
    
    let bind: std::net::SocketAddr = std::env::var("PCE_BIND")
        .unwrap_or_else(|_| "0.0.0.0:3032".to_string())
        .parse()
        .expect("invalid PCE_BIND");
    warp::serve(routes).run(bind).await;
}

/// Handle privacy transformation
async fn handle_transform(
    req: TransformRequest,
    state: PceState,
) -> Result<impl warp::Reply, warp::Rejection> {
    println!("🔐 Transform session: {} | source: {}", req.session_id, req.source);
    
    // Parse evidence
    let mut evidence: serde_json::Value = serde_json::from_str(&req.evidence)
        .map_err(|_| warp::reject::custom(ParseError))?;
    
    // Initialize managers
    let mut pseudonym_mgr = PseudonymManager::new(req.session_id.clone());
    
    // Select policy based on source
    let policy = match req.source.as_str() {
        "Tpm" => DisclosurePolicy::for_tpm(),
        "Tdx" => DisclosurePolicy::for_tdx(),
        "SevSnp" => DisclosurePolicy::for_snp(),
        "Cca" => DisclosurePolicy::for_cca(),
        "OpTee" => DisclosurePolicy::for_optee(),
        _ => {
            println!("   ❌ Unsupported source: {}", req.source);
            return Err(warp::reject::custom(UnsupportedSourceError));
        }
    };
    
    // Detect risks (source-aware)
    let risks = pseudonym_mgr.detect_risks(&evidence, &req.source);
    if !risks.is_empty() {
        println!("   ⚠️  {} risks detected", risks.len());
    }
    
    // Apply pseudonymization (source-aware) + store in DB
    pseudonymize_and_store(&mut evidence, &mut pseudonym_mgr, &req.source, &req.session_id, &state.store).await;
    
    // Apply disclosure policy
    let manifest = policy.apply(&mut evidence);
    
    println!("   ✅ Done: {} redacted, {} aggregated", 
        manifest.redacted_fields.len(),
        manifest.aggregated_fields.len()
    );
    
    // Serialize
    let transformed = serde_json::to_string(&evidence)
        .map_err(|_| warp::reject::custom(SerializationError))?;
    
    Ok(warp::reply::json(&TransformResponse {
        transformed_evidence: transformed,
        manifest,
        risks,
    }))
}

/// Pseudonymize known stable identifier fields + store in DB + extract public keys
async fn pseudonymize_and_store(
    evidence: &mut serde_json::Value,
    pseudonym_mgr: &mut PseudonymManager,
    source: &str,
    session_id: &str,
    store: &Arc<dyn PseudonymStore>,
) {
    let fields: Vec<&str> = match source {
        "Tpm" => vec!["aik_cert", "ek_cert", "qualified_signer"],
        "Tdx" => vec!["mrseam", "mrtd", "mrconfigid", "mrowner", "mrownerconfig"],
        "SevSnp" => vec!["vcek_cert", "chip_id", "id_key_digest", "author_key_digest"],
        "Cca" => vec!["instance_id", "realm_public_key", "signer_id"],
        "OpTee" => vec!["attestation_key_fpr"],
        _ => vec![],
    };
    
    for field in &fields {
        if let Some(value) = evidence.get(field) {
            if let Some(val_str) = value.as_str() {
                if val_str.len() > 10 {
                    let pseudonym = pseudonym_mgr.pseudonymize(field, val_str);
                    
                    // Hash original value for privacy
                    let mut hasher = Sha256::new();
                    hasher.update(val_str.as_bytes());
                    let original_hash = format!("{:x}", hasher.finalize());
                    
                    // Check if this is a certificate → extract public key
                    let mut public_key_id = None;
                    if field.ends_with("_cert") && is_pem_certificate(val_str) {
                        if let Ok(mut pubkey) = extract_public_key_from_cert(val_str) {
                            // Set source based on field name
                            pubkey.source = match *field {
                                "aik_cert" => "TPM_AIK",
                                "ek_cert" => "TPM_EK",
                                "vcek_cert" => "SNP_VCEK",
                                _ => "Unknown",
                            }.to_string();
                            
                            // Store public key
                            if let Ok(key_id) = store.store_public_key(pubkey).await {
                                public_key_id = Some(key_id);
                                println!("   🔑 Extracted public key from {}", field);
                            }
                        }
                    }
                    
                    // Store mapping in DB
                    let mapping = PseudonymMapping {
                        id: None,
                        session_id: session_id.to_string(),
                        field_name: field.to_string(),
                        original_hash,
                        pseudonym: pseudonym.clone(),
                        public_key_id,
                        created_at: Utc::now(),
                    };
                    
                    if let Err(e) = store.store_mapping(mapping).await {
                        println!("   ⚠️  Failed to store mapping for {}: {}", field, e);
                    }
                    
                    // Replace with pseudonym
                    if let Some(obj) = evidence.as_object_mut() {
                        obj.insert(field.to_string(), serde_json::Value::String(pseudonym));
                        println!("   🎭 Pseudonymized: {}", field);
                    }
                }
            }
        }
    }
}

/// Handle validation
async fn handle_validate(
    req: ValidateNodeRequest,
    state: PceState,
) -> Result<impl warp::Reply, warp::Rejection> {
    println!("📋 Validating node");
    
    let policy = match state.policies.values().next() {
        Some(p) => p,
        None => {
            return Ok(warp::reply::json(&ValidateNodeResponse {
                result: ComplianceResult {
                    status: pce_service::policy::ComplianceStatus::Unknown,
                    violations: vec![],
                    validated_at: chrono::Utc::now(),
                    policy_version: "none".to_string(),
                },
            }));
        }
    };
    
    let applicable = policy.find_applicable_policies(&req.node);
    
    if applicable.is_empty() {
        return Ok(warp::reply::json(&ValidateNodeResponse {
            result: ComplianceResult {
                status: pce_service::policy::ComplianceStatus::Unknown,
                violations: vec![],
                validated_at: chrono::Utc::now(),
                policy_version: policy.version.clone(),
            },
        }));
    }
    
    let mut violations = Vec::new();
    for component in applicable {
        let result = validate_node(&req.node, &component.rules, &policy.version);
        violations.extend(result.violations);
    }
    
    let status = if violations.is_empty() {
        pce_service::policy::ComplianceStatus::Compliant
    } else {
        pce_service::policy::ComplianceStatus::NonCompliant
    };
    
    Ok(warp::reply::json(&ValidateNodeResponse {
        result: ComplianceResult {
            status,
            violations,
            validated_at: chrono::Utc::now(),
            policy_version: policy.version.clone(),
        },
    }))
}

/// Handle pseudonym resolution
async fn handle_resolve(
    req: ResolvePseudonymRequest,
    state: PceState,
) -> Result<impl warp::Reply, warp::Rejection> {
    println!("🔍 Resolving pseudonym: {} (session: {})", req.pseudonym, req.session_id);
    
    match state.store.resolve(&req.session_id, &req.pseudonym).await {
        Ok(resolved) => {
            println!("   ✅ Resolved: {} → {}", req.pseudonym, resolved.field_name);
            Ok(warp::reply::json(&ResolvePseudonymResponse {
                pseudonym: resolved.pseudonym,
                field_name: resolved.field_name,
                public_key_pem: resolved.public_key_pem,
                key_type: resolved.key_type,
                source: resolved.source,
            }))
        }
        Err(e) => {
            println!("   ❌ Not found: {}", e);
            Err(warp::reject::custom(PseudonymNotFoundError))
        }
    }
}

/// Handle health check
async fn handle_health(
    state: PceState,
) -> Result<impl warp::Reply, warp::Rejection> {
    let db_healthy = state.store.health_check().await;
    
    Ok(warp::reply::json(&serde_json::json!({
        "status": if db_healthy { "ok" } else { "degraded" },
        "database": if db_healthy { "connected" } else { "disconnected" }
    })))
}

fn load_policies(path: &str) -> Result<HashMap<String, Policy>, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let policy: Policy = serde_json::from_str(&content)?;
    
    let mut policies = HashMap::new();
    policies.insert("default".to_string(), policy);
    
    Ok(policies)
}

#[derive(Debug)]
struct ParseError;
impl warp::reject::Reject for ParseError {}

#[derive(Debug)]
struct SerializationError;
impl warp::reject::Reject for SerializationError {}

#[derive(Debug)]
struct UnsupportedSourceError;
impl warp::reject::Reject for UnsupportedSourceError {}

#[derive(Debug)]
struct PseudonymNotFoundError;
impl warp::reject::Reject for PseudonymNotFoundError {}