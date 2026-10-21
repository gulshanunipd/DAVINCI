//! Attestation Manager Service
//!
//! Orchestrates the DAVINCI attester side (D3 §8). On every collection it:
//!   1. drives the MRAL, which calls each Root of Trust's collector on the
//!      attested platform and verifies the evidence natively — Collect/Auth,
//!   2. applies the PCE privacy transform (fail-closed) — Transform,
//!   3. inserts hash-linked AMC nodes and builds the ARG with AM-signed trust
//!      edges — Attest,
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
use openssl::pkey::{PKey, Private};
use crate::amc::{AcmChain, AcmNode};
use crate::arg::AttestationRecordGraph;
use crate::amc::Layer;
use crate::arg::ArgEdge;
use crate::mral::{CollectedNode, Mral, MralConfig};

/// Request to collect fresh evidence from all Roots of Trust.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CollectRequest {
    session_id: String,
    /// Verifier challenge; every RoT signature is bound to it.
    nonce: String,
}

/// Per-node outcome of a collection.
#[derive(Debug, Clone, Serialize)]
struct NodeResult {
    layer: String,
    source: String,
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
    last_nodes: HashMap<Layer, Uuid>,
    manifests: Vec<PceDisclosureManifest>,
}

impl SessionState {
    fn new() -> Self {
        SessionState {
            arg: AttestationRecordGraph::new(),
            last_nodes: HashMap::new(),
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
    /// Multi-RoT Abstraction Layer (collectors + RoT trust material).
    mral: Arc<Mral>,
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

    // MRAL: where the RoT collectors run and where RoT trust material lives.
    let mral = Mral::new(MralConfig {
        tpm_url: env::var("MRAL_TPM_URL").unwrap_or_else(|_| "http://localhost:4010".to_string()),
        optee_url: env::var("MRAL_OPTEE_URL")
            .unwrap_or_else(|_| "http://localhost:4020/cgi-bin/attest".to_string()),
        trust_dir: env::var("DAVINCI_TRUST_DIR").unwrap_or_else(|_| format!("{}/rot", keys_dir)),
        store_path: format!("{}/enrollment.json", keys_dir),
    });
    let enrolled = mral.enrollment();

    let state = AppState {
        amc_chain: Arc::new(Mutex::new(AcmChain::new())),
        sessions: Arc::new(Mutex::new(HashMap::new())),
        pce_client: reqwest::Client::new(),
        am_key: Arc::new(am_key),
        am_pub_pem: Arc::new(am_pub_pem),
        mral: Arc::new(mral),
        pce_url,
    };

    // Enrollment of the Roots of Trust (provisioning step).
    let enroll = warp::path!("mral" / "enroll")
        .and(warp::post())
        .and(with_state(state.clone()))
        .and_then(handle_enroll);

    let mral_status = warp::path!("mral" / "status")
        .and(warp::get())
        .and(with_state(state.clone()))
        .and_then(handle_mral_status);

    // Collect fresh, challenge-bound evidence from every RoT (Collect → Transform → Attest).
    let collect = warp::path!("attest" / "collect")
        .and(warp::post())
        .and(with_state(state.clone()))
        .and(warp::body::json::<CollectRequest>())
        .and_then(handle_collect);

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

    let routes = enroll
        .or(mral_status)
        .or(collect)
        .or(attest_output)
        .or(get_arg)
        .or(pubkey)
        .with(warp::cors().allow_any_origin());

    let cfg = state.mral.config();
    println!("🔐 Attestation Manager on {}", bind);
    println!("   PCE (fail-closed) at {}", state.pce_url);
    println!("   MRAL TPM collector   {}", cfg.tpm_url);
    println!("   MRAL OP-TEE collector {}", cfg.optee_url);
    println!(
        "   enrolled RoTs: tpm={} optee={}",
        enrolled.tpm.is_some(),
        enrolled.optee.is_some()
    );
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

/// Map an evidence source to the PCE disclosure-profile name.
fn pce_source_name(source: &amc::Source) -> &'static str {
    match source {
        amc::Source::Tpm | amc::Source::Ima | amc::Source::Evm => "Tpm",
        amc::Source::SevSnp => "SevSnp",
        amc::Source::Tdx => "Tdx",
        amc::Source::Cca => "Cca",
        amc::Source::OpTee => "OpTee",
    }
}

/// Handler for RoT enrollment.
async fn handle_enroll(state: AppState) -> Result<impl warp::Reply, warp::Rejection> {
    println!("🪪 MRAL enrollment");
    let reports = state.mral.enroll().await;
    for r in &reports {
        match &r.error {
            None => println!("   ✅ {} enrolled", r.rot),
            Some(e) => println!("   ❌ {} not enrolled: {}", r.rot, e),
        }
    }
    let ok = reports.iter().all(|r| r.verified);
    Ok(warp::reply::json(&json!({ "enrolled": ok, "rots": reports })))
}

/// Current enrollment (trusted RoT keys).
async fn handle_mral_status(state: AppState) -> Result<impl warp::Reply, warp::Rejection> {
    Ok(warp::reply::json(&state.mral.enrollment()))
}

/// Handler for a collection round: Collect/Auth (MRAL) → Transform → Attest.
async fn handle_collect(
    state: AppState,
    request: CollectRequest,
) -> Result<impl warp::Reply, warp::Rejection> {
    println!(
        "📥 collect | session '{}' | challenge '{}'",
        request.session_id, request.nonce
    );
    let (nodes, rot_reports) = state.mral.collect(&request.session_id, &request.nonce).await;
    for r in &rot_reports {
        match &r.error {
            None => println!("   ✅ Auth OK: {} evidence verified", r.rot),
            Some(e) => println!("   ❌ Auth failed: {}: {}", r.rot, e),
        }
    }

    let mut results = Vec::new();
    for node in nodes {
        results.push(admit_node(&state, &request.session_id, node).await);
    }
    let status = if rot_reports.iter().all(|r| r.verified)
        && results.iter().all(|r| r.status == "success")
    {
        "success"
    } else {
        "partial"
    };
    Ok(warp::reply::json(&json!({
        "status": status,
        "rots": rot_reports,
        "nodes": results,
    })))
}

/// Transform (PCE, fail-closed) and Attest (AMC + ARG) one verified node.
async fn admit_node(state: &AppState, session_id: &str, node: CollectedNode) -> NodeResult {
    let layer_name = format!("{:?}", node.layer);
    let source_name = format!("{:?}", node.source);
    let fail = |status: String| NodeResult {
        layer: layer_name.clone(),
        source: source_name.clone(),
        status,
        node_id: None,
        privacy_manifest: None,
        privacy_risks: None,
    };

    // Transform / PCE (fail-closed: no privacy → no admission).
    let evidence_str = node.evidence.to_string();
    let pce = match call_pce_transformation(
        &state.pce_client,
        &state.pce_url,
        session_id,
        pce_source_name(&node.source),
        &evidence_str,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            println!("   ❌ PCE unavailable, failing closed: {}", e);
            return fail(format!("rejected_pce_unavailable: {}", e));
        }
    };
    println!(
        "   🔒 PCE {}: {} redacted, {} aggregated, {} risks",
        layer_name,
        pce.manifest.redacted_fields.len(),
        pce.manifest.aggregated_fields.len(),
        pce.risks.len()
    );

    // Attest: AMC insert (hash-linked) + ARG node with AM-signed edge.
    let amc_node = AcmNode::new(node.layer.clone(), node.mode, node.source, pce.transformed_evidence, None, None);
    let linked = {
        let mut chain = state.amc_chain.lock().unwrap();
        chain.add_node(amc_node)
    };
    let node_id = linked.jti;
    let node_hash = linked.hash.clone();

    {
        let mut sessions = state.sessions.lock().unwrap();
        let session = sessions
            .entry(session_id.to_string())
            .or_insert_with(SessionState::new);

        if let Some((parent_layer, relationship)) = node.parent {
            match session
                .last_nodes
                .get(&parent_layer)
                .and_then(|pid| session.arg.nodes.get(pid).map(|n| (*pid, n.hash.clone())))
            {
                Some((parent_id, parent_hash)) => {
                    let msg = arg::edge_signing_message(
                        &node_id,
                        &parent_id,
                        &relationship,
                        &node_hash,
                        &parent_hash,
                    );
                    let signature = crypto::sign_hex(&state.am_key, msg.as_bytes()).ok();
                    if signature.is_some() {
                        println!("   🔗 AM-signed edge {:?} → {:?}", node.layer, parent_layer);
                    }
                    session.arg.add_edge(ArgEdge {
                        from: node_id,
                        to: parent_id,
                        relationship,
                        signature,
                    });
                }
                None => println!("   ⚠️  no admitted {:?} node to anchor {:?}", parent_layer, node.layer),
            }
        }

        session.arg.add_node(linked);
        session.last_nodes.insert(node.layer, node_id);
        session.manifests.push(pce.manifest.clone());
    }

    NodeResult {
        layer: layer_name,
        source: source_name,
        status: "success".to_string(),
        node_id: Some(node_id),
        privacy_manifest: Some(pce.manifest),
        privacy_risks: Some(pce.risks),
    }
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
