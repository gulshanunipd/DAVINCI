//! Attestation Manager Service
//!
//! Orchestrates the DAVINCI attester side (D3 §8). For each evidence item it:
//!   1. runs the MRAL `Auth` check (RoT signature over µ|ts) — Collect,
//!   2. applies the PCE privacy transform (fail-closed) — Transform,
//!   3. inserts a hash-linked AMC node and builds the ARG with AM-signed
//!      trust edges — Attest,
//! and exposes a signed, challenge-bound attestation output for the Verifier.

mod amc;
mod arg;
mod crypto;
mod mral;

use warp::Filter;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::env;
use std::fs;
use chrono::Utc;
use openssl::pkey::{PKey, Private, Public};
use crate::amc::{AcmChain, AcmNode};
use crate::arg::AttestationRecordGraph;
use crate::amc::Layer;
use crate::arg::{ArgEdge, ArgRelationship};

/// Request to add boot-time evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BootAttestationRequest {
    session_id: String,
    layer: String,
    source: String,
    /// Raw evidence envelope (JSON string): {source, measurement, ts, claims, rot_sig, ...}
    evidence: String,
}

/// Request to add runtime evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RuntimeAttestationRequest {
    session_id: String,
    evidence: String,
}

/// Response for an attestation submission
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AttestationResponse {
    status: String,
    node_id: Option<Uuid>,
    privacy_manifest: Option<PceDisclosureManifest>,
    privacy_risks: Option<Vec<PcePrivacyRisk>>,
}

/// PCE transformation request
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PceTransformRequest {
    session_id: String,
    source: String,
    evidence: String,
}

/// PCE transformation response
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PceTransformResponse {
    transformed_evidence: String,
    manifest: PceDisclosureManifest,
    risks: Vec<PcePrivacyRisk>,
}

/// PCE disclosure manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PceDisclosureManifest {
    redacted_fields: Vec<String>,
    aggregated_fields: Vec<(String, String)>,
    retained_fields: Vec<String>,
}

/// PCE privacy risk
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PcePrivacyRisk {
    risk_type: String,
    field: String,
    severity: String,
}

/// Per-session attester state.
#[derive(Clone)]
struct SessionState {
    arg: AttestationRecordGraph,
    last_boot_nodes: HashMap<Layer, Uuid>,
    manifests: Vec<PceDisclosureManifest>,
}

impl SessionState {
    fn new() -> Self {
        SessionState {
            arg: AttestationRecordGraph::new(),
            last_boot_nodes: HashMap::new(),
            manifests: Vec::new(),
        }
    }
}

/// Shared service state.
#[derive(Clone)]
struct AppState {
    amc_chain: Arc<Mutex<AcmChain>>,
    sessions: Arc<Mutex<HashMap<String, SessionState>>>,
    pce_client: reqwest::Client,
    /// AM signing key sk_AM (D3 Setup).
    am_key: Arc<PKey<Private>>,
    /// AM public key PEM (τ) served to the Verifier.
    am_pub_pem: Arc<String>,
    /// Trusted material: per-source RoT public keys pk_r (D3 §9).
    rot_pubkeys: Arc<HashMap<String, PKey<Public>>>,
    /// PCE base URL (env PCE_URL).
    pce_url: String,
}

#[tokio::main]
async fn main() {
    let keys_dir = env::var("DAVINCI_KEYS_DIR").unwrap_or_else(|_| "../keys".to_string());
    let pce_url = env::var("PCE_URL").unwrap_or_else(|_| "http://localhost:3032".to_string());
    let bind: std::net::SocketAddr = env::var("AM_BIND")
        .unwrap_or_else(|_| "0.0.0.0:3030".to_string())
        .parse()
        .expect("invalid AM_BIND");

    // Setup: load the AM key pair (sk_AM, pk_AM) — the trust anchor τ = pk_AM.
    let am_key = crypto::load_private_key(&format!("{}/am_priv.pem", keys_dir))
        .expect("load AM private key (run keys/gen-keys.sh?)");
    let am_pub_pem = fs::read_to_string(format!("{}/am_pub.pem", keys_dir))
        .expect("read AM public key PEM");

    // Load per-source RoT public keys (trusted material tm_r).
    let mut rot_pubkeys = HashMap::new();
    for src in ["tpm", "snp", "tdx", "cca", "ima"] {
        match crypto::load_public_key(&format!("{}/rot_{}_pub.pem", keys_dir, src)) {
            Ok(k) => {
                rot_pubkeys.insert(src.to_string(), k);
            }
            Err(e) => println!("⚠️  RoT key for '{}' not loaded: {}", src, e),
        }
    }

    let state = AppState {
        amc_chain: Arc::new(Mutex::new(AcmChain::new())),
        sessions: Arc::new(Mutex::new(HashMap::new())),
        pce_client: reqwest::Client::new(),
        am_key: Arc::new(am_key),
        am_pub_pem: Arc::new(am_pub_pem),
        rot_pubkeys: Arc::new(rot_pubkeys),
        pce_url,
    };

    let boot_attest = warp::path("attest")
        .and(warp::path("boot"))
        .and(warp::post())
        .and(with_state(state.clone()))
        .and(warp::body::json::<BootAttestationRequest>())
        .and_then(handle_boot_attestation);

    let runtime_attest = warp::path("attest")
        .and(warp::path("runtime"))
        .and(warp::post())
        .and(with_state(state.clone()))
        .and(warp::body::json::<RuntimeAttestationRequest>())
        .and_then(handle_runtime_attestation);

    // Signed, challenge-bound attestation output (the Attest export consumed by Verify).
    let attest_output = warp::path("attest")
        .and(warp::path("output"))
        .and(warp::path::param::<String>())
        .and(warp::get())
        .and(warp::query::<HashMap<String, String>>())
        .and(with_state(state.clone()))
        .and_then(|sid, q, st| handle_attest_output(st, sid, q));

    // Raw (unsigned) ARG for debugging/inspection.
    let get_arg = warp::path("arg")
        .and(warp::path::param::<String>())
        .and(warp::get())
        .and(with_state(state.clone()))
        .and_then(|sid, st| handle_get_arg(st, sid));

    // Trust anchor distribution: τ = pk_AM.
    let pubkey = warp::path("pubkey")
        .and(warp::get())
        .and(with_state(state.clone()))
        .and_then(handle_pubkey);

    let routes = boot_attest
        .or(runtime_attest)
        .or(attest_output)
        .or(get_arg)
        .or(pubkey)
        .with(warp::cors().allow_any_origin());

    println!("🔐 Attestation Manager on {}", bind);
    println!("   PCE (fail-closed) at {}", state.pce_url);
    println!("   RoT trust material loaded for {} source(s)", state.rot_pubkeys.len());
    warp::serve(routes).run(bind).await;
}

/// Call PCE to transform evidence with privacy protections.
async fn call_pce_transformation(
    client: &reqwest::Client,
    pce_url: &str,
    session_id: &str,
    source: &str,
    evidence: &str,
) -> Result<PceTransformResponse, String> {
    let request = PceTransformRequest {
        session_id: session_id.to_string(),
        source: source.to_string(),
        evidence: evidence.to_string(),
    };

    let response = client
        .post(format!("{}/privacy/transform", pce_url.trim_end_matches('/')))
        .json(&request)
        .send()
        .await
        .map_err(|e| format!("PCE request failed: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("PCE returned HTTP {}", response.status()));
    }

    response
        .json::<PceTransformResponse>()
        .await
        .map_err(|e| format!("PCE response parse failed: {}", e))
}

/// Map the request source string to the PCE source enum name.
fn pce_source_name(source: &str) -> Option<&'static str> {
    match source.to_lowercase().as_str() {
        "tpm" => Some("Tpm"),
        "snp" => Some("SevSnp"),
        "tdx" => Some("Tdx"),
        "cca" => Some("Cca"),
        "ima" => Some("Tpm"), // IMA log rides the TPM disclosure profile
        _ => None,
    }
}

fn reject(status: String) -> Result<warp::reply::Json, warp::Rejection> {
    Ok(warp::reply::json(&AttestationResponse {
        status,
        node_id: None,
        privacy_manifest: None,
        privacy_risks: None,
    }))
}

/// Handler for boot-time attestation requests.
async fn handle_boot_attestation(
    state: AppState,
    request: BootAttestationRequest,
) -> Result<impl warp::Reply, warp::Rejection> {
    println!(
        "📥 boot attest | session '{}' | layer {} | source {}",
        request.session_id, request.layer, request.source
    );

    let layer = match request.layer.as_str() {
        "platform" => Layer::Platform,
        "hypervisor" => Layer::Hypervisor,
        "guest" => Layer::Guest,
        _ => Layer::Platform,
    };
    let source = match request.source.to_lowercase().as_str() {
        "snp" => amc::Source::SevSnp,
        "tdx" => amc::Source::Tdx,
        "cca" => amc::Source::Cca,
        _ => amc::Source::Tpm,
    };
    let parent_layer = match layer {
        Layer::Platform => None,
        Layer::Hypervisor => Some(Layer::Platform),
        Layer::Guest => Some(Layer::Hypervisor),
        Layer::Application => Some(Layer::Guest),
    };

    process_evidence(
        state,
        request.session_id,
        request.source,
        request.evidence,
        layer,
        amc::Mode::BootTime,
        source,
        parent_layer,
        ArgRelationship::VmIncludesHypervisor,
    )
    .await
}

/// Handler for runtime (IMA) attestation requests.
async fn handle_runtime_attestation(
    state: AppState,
    request: RuntimeAttestationRequest,
) -> Result<impl warp::Reply, warp::Rejection> {
    println!("📥 runtime attest | session '{}'", request.session_id);

    process_evidence(
        state,
        request.session_id,
        "ima".to_string(),
        request.evidence,
        Layer::Application,
        amc::Mode::Runtime,
        amc::Source::Ima,
        Some(Layer::Guest),
        ArgRelationship::RuntimeLinkedToBoot,
    )
    .await
}

/// Shared Collect → Transform → Attest pipeline for one evidence item.
#[allow(clippy::too_many_arguments)]
async fn process_evidence(
    state: AppState,
    session_id: String,
    source_str: String,
    evidence_str: String,
    layer: Layer,
    mode: amc::Mode,
    source: amc::Source,
    parent_layer: Option<Layer>,
    relationship: ArgRelationship,
) -> Result<warp::reply::Json, warp::Rejection> {
    // Parse the raw evidence envelope.
    let evidence: serde_json::Value = match serde_json::from_str(&evidence_str) {
        Ok(v) => v,
        Err(e) => return reject(format!("rejected_parse: {}", e)),
    };

    // 1. Collect / MRAL Auth: verify the RoT signature before admission.
    let src_key = source_str.to_lowercase();
    match state.rot_pubkeys.get(&src_key) {
        None => return reject(format!("rejected_unknown_source: {}", source_str)),
        Some(rot_pub) => {
            if let Err(e) = mral::verify_rot_auth(&evidence, rot_pub) {
                println!("   ❌ Auth failed: {}", e);
                return reject(format!("rejected_auth: {}", e));
            }
        }
    }
    println!("   ✅ Auth OK (RoT signature valid)");

    // 2. Transform / PCE (fail-closed: no privacy → no admission).
    let pce_source = match pce_source_name(&source_str) {
        Some(s) => s,
        None => return reject(format!("rejected_unknown_source: {}", source_str)),
    };
    let pce = match call_pce_transformation(
        &state.pce_client,
        &state.pce_url,
        &session_id,
        pce_source,
        &evidence_str,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            println!("   ❌ PCE unavailable, failing closed: {}", e);
            return reject(format!("rejected_pce_unavailable: {}", e));
        }
    };
    println!(
        "   🔒 PCE: {} redacted, {} aggregated, {} risks",
        pce.manifest.redacted_fields.len(),
        pce.manifest.aggregated_fields.len(),
        pce.risks.len()
    );

    // 3. Attest: AMC insert (hash-linked) + ARG node with AM-signed edge.
    let node = AcmNode::new(layer.clone(), mode, source, pce.transformed_evidence, None, None);
    let linked = {
        let mut chain = state.amc_chain.lock().unwrap();
        chain.add_node(node)
    };
    let node_id = linked.jti;
    let node_hash = linked.hash.clone();

    {
        let mut sessions = state.sessions.lock().unwrap();
        let session = sessions
            .entry(session_id.clone())
            .or_insert_with(SessionState::new);

        if let Some(pl) = parent_layer {
            if let Some(&parent_id) = session.last_boot_nodes.get(&pl) {
                if let Some(parent_hash) =
                    session.arg.nodes.get(&parent_id).map(|n| n.hash.clone())
                {
                    let msg = arg::edge_signing_message(
                        &node_id,
                        &parent_id,
                        &relationship,
                        &node_hash,
                        &parent_hash,
                    );
                    let signature = crypto::sign_hex(&state.am_key, msg.as_bytes()).ok();
                    if signature.is_some() {
                        println!("   🔗 AM-signed edge {} → {}", node_id, parent_id);
                    }
                    session.arg.add_edge(ArgEdge {
                        from: node_id,
                        to: parent_id,
                        relationship,
                        signature,
                    });
                } else {
                    println!("   ⚠️  parent {:?} node missing from ARG", pl);
                }
            } else {
                println!("   ⚠️  no parent node for layer {:?}", pl);
            }
        }

        session.arg.add_node(linked);
        // Only boot-time nodes are chain parents for later layers.
        session.last_boot_nodes.insert(layer, node_id);
        session.manifests.push(pce.manifest.clone());
    }

    Ok(warp::reply::json(&AttestationResponse {
        status: "success".to_string(),
        node_id: Some(node_id),
        privacy_manifest: Some(pce.manifest),
        privacy_risks: Some(pce.risks),
    }))
}

/// Export the signed, challenge-bound attestation output (Attest → Verify).
async fn handle_attest_output(
    state: AppState,
    session_id: String,
    query: HashMap<String, String>,
) -> Result<impl warp::Reply, warp::Rejection> {
    let nonce = query.get("nonce").cloned().unwrap_or_default();
    println!("📤 attest output | session '{}' | nonce '{}'", session_id, nonce);

    let (arg_json, manifest_json) = {
        let sessions = state.sessions.lock().unwrap();
        match sessions.get(&session_id) {
            Some(session) => {
                let arg_json = session.arg.to_json().unwrap_or_else(|_| "{}".to_string());
                let (mut red, mut agg, mut ret) = (0usize, 0usize, 0usize);
                for m in &session.manifests {
                    red += m.redacted_fields.len();
                    agg += m.aggregated_fields.len();
                    ret += m.retained_fields.len();
                }
                let manifest_json = format!(
                    "{{\"redacted\":{},\"aggregated\":{},\"retained\":{}}}",
                    red, agg, ret
                );
                (arg_json, manifest_json)
            }
            None => (
                "{\"nodes\":{},\"edges\":[]}".to_string(),
                "{\"redacted\":0,\"aggregated\":0,\"retained\":0}".to_string(),
            ),
        }
    };

    let ts_out = Utc::now().timestamp();
    // pf = ECDSA_{sk_AM}( sid \n challenge \n ts_out \n manifest \n G' ) — D3 Eq. 11.
    let msg = format!(
        "{}\n{}\n{}\n{}\n{}",
        session_id, nonce, ts_out, manifest_json, arg_json
    );
    let pf = crypto::sign_hex(&state.am_key, msg.as_bytes()).unwrap_or_default();

    let manifest_val: serde_json::Value =
        serde_json::from_str(&manifest_json).unwrap_or(json!({}));
    let arg_val: serde_json::Value = serde_json::from_str(&arg_json).unwrap_or(json!({}));

    Ok(warp::reply::json(&json!({
        "out": {
            "sid": session_id,
            "challenge": nonce,
            "ts_out": ts_out,
            "manifest": manifest_val,
            "manifest_str": manifest_json,
            "arg": arg_val,
            "arg_str": arg_json,
        },
        "pf": pf,
    })))
}

/// Raw ARG retrieval (debugging).
async fn handle_get_arg(
    state: AppState,
    session_id: String,
) -> Result<impl warp::Reply, warp::Rejection> {
    let sessions = state.sessions.lock().unwrap();
    let arg_json = match sessions.get(&session_id) {
        Some(session) => session.arg.to_json().unwrap_or_else(|_| "{}".to_string()),
        None => AttestationRecordGraph::new().to_json().unwrap(),
    };
    Ok(warp::reply::json(&json!({ "arg": arg_json })))
}

/// Serve the AM public key (trust anchor τ).
async fn handle_pubkey(state: AppState) -> Result<impl warp::Reply, warp::Rejection> {
    Ok(warp::reply::json(&json!({ "pubkey_pem": state.am_pub_pem.as_str() })))
}

fn with_state(
    state: AppState,
) -> impl Filter<Extract = (AppState,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || state.clone())
}
