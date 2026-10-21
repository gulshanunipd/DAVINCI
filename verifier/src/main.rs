//! Verifier Service
//!
//! Implements the concrete DAVINCI `Verify` (D3 §5.7): it fetches the signed
//! attestation output from the AM, checks the AM's ECDSA-P256 signature over the
//! output, confirms the challenge it issued is bound in, evaluates the
//! graph-validity predicate ϕ_G, and appraises every node's evidence (RoT-level
//! freshness, reference values). The trust decision is the conjunction — not a
//! guess based on the session name.
//!
//! Challenges are issued by this service (`GET /challenge`), expire after
//! `CHALLENGE_TTL_SECS` and are single-use, so a recorded attestation cannot
//! be replayed against a later verification.

mod crypto;
mod verification;

use warp::Filter;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use std::env;
use std::net::SocketAddr;
use openssl::pkey::{PKey, Public};
use crate::verification::{
    appraise_evidence, produce_trust_decision, verify_graph, VerificationDetail, VerificationResult,
};

const CHALLENGE_TTL_SECS: u64 = 300;

/// Request to verify an attestation session.
#[derive(Debug, Clone, Deserialize)]
struct VerifyRequest {
    session_id: String,
    /// Fresh verifier challenge c (must be bound into the AM output).
    nonce: String,
}

/// Response with the verification result.
#[derive(Debug, Clone, Serialize)]
struct VerifyResponse {
    result: VerificationResult,
}

#[derive(Clone)]
struct VState {
    /// Trust anchor τ = pk_AM, loaded out-of-band from the keys directory.
    am_pub: Arc<PKey<Public>>,
    am_url: String,
    client: reqwest::Client,
    /// Outstanding challenges → issue time (unix seconds).
    challenges: Arc<Mutex<HashMap<String, u64>>>,
    /// Reference values (endorsed measurements), re-read on every verification.
    reference_path: String,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

#[tokio::main]
async fn main() {
    let keys_dir = env::var("DAVINCI_KEYS_DIR").unwrap_or_else(|_| "../keys".to_string());
    let am_pub = crypto::load_public_key(&format!("{}/am_pub.pem", keys_dir))
        .expect("load AM public key (trust anchor τ)");
    let am_url = env::var("ATTESTATION_MANAGER_URL")
        .unwrap_or_else(|_| "http://localhost:3030".to_string());
    let bind: SocketAddr = env::var("VERIFIER_BIND")
        .unwrap_or_else(|_| "0.0.0.0:3031".to_string())
        .parse()
        .expect("invalid VERIFIER_BIND");
    let reference_path = env::var("DAVINCI_REFERENCE")
        .unwrap_or_else(|_| "../reference/reference-values.json".to_string());

    let state = VState {
        am_pub: Arc::new(am_pub),
        am_url,
        client: reqwest::Client::new(),
        challenges: Arc::new(Mutex::new(HashMap::new())),
        reference_path,
    };

    let challenge = warp::path("challenge")
        .and(warp::get())
        .and(with_state(state.clone()))
        .map(|st: VState| {
            let mut buf = [0u8; 32];
            openssl::rand::rand_bytes(&mut buf).expect("rng");
            let nonce = hex::encode(buf);
            let mut ch = st.challenges.lock().unwrap();
            ch.retain(|_, t| now() - *t <= CHALLENGE_TTL_SECS);
            ch.insert(nonce.clone(), now());
            warp::reply::json(&json!({ "nonce": nonce, "expires_in": CHALLENGE_TTL_SECS }))
        });

    let verify = warp::path("verify")
        .and(warp::path::end())
        .and(warp::post())
        .and(with_state(state.clone()))
        .and(warp::body::json::<VerifyRequest>())
        .and_then(handle_verify);

    let health = warp::path("health")
        .and(warp::get())
        .map(|| warp::reply::json(&json!({ "status": "ok" })));

    let routes = verify.or(challenge).or(health).with(warp::cors().allow_any_origin());

    println!("🔎 Verifier on {}", bind);
    println!("   Attestation Manager at {}", state.am_url);
    println!("   Reference values      {}", state.reference_path);
    warp::serve(routes).run(bind).await;
}

async fn handle_verify(
    state: VState,
    request: VerifyRequest,
) -> Result<impl warp::Reply, warp::Rejection> {
    println!(
        "🔎 verify | session '{}' | challenge '{}'",
        request.session_id, request.nonce
    );
    let mut details: Vec<VerificationDetail> = Vec::new();

    // The challenge must be one we issued, unexpired, and unused (consumed now).
    let issued = state.challenges.lock().unwrap().remove(&request.nonce);
    let live = matches!(issued, Some(t) if now() - t <= CHALLENGE_TTL_SECS);
    details.push(mk(
        "Challenge Issued by Verifier (single-use, unexpired)",
        live,
        "unknown, expired or already-used challenge (replay)",
    ));

    // Fetch the signed attestation output (out, pf) from the AM, binding our nonce.
    let url = format!(
        "{}/attest/output/{}",
        state.am_url.trim_end_matches('/'),
        request.session_id
    );
    let resp = state
        .client
        .get(&url)
        .query(&[("nonce", request.nonce.as_str())])
        .send()
        .await;

    let body: Value = match resp {
        Ok(r) => match r.json().await {
            Ok(v) => v,
            Err(e) => {
                return Ok(fail_now("AM Output Retrieval", &format!("parse error: {}", e)));
            }
        },
        Err(e) => {
            return Ok(fail_now("AM Output Retrieval", &format!("request error: {}", e)));
        }
    };

    let out = &body["out"];
    let pf = body["pf"].as_str().unwrap_or("");
    let sid = out["sid"].as_str().unwrap_or("");
    let challenge = out["challenge"].as_str().unwrap_or("");
    let ts_out = out["ts_out"].as_i64().unwrap_or(0);
    let manifest_str = out["manifest_str"].as_str().unwrap_or("");
    let arg_str = out["arg_str"].as_str().unwrap_or("");

    // 1. Output integrity: ECDSA.verify(pk_AM, out, pf).
    let msg = format!("{}\n{}\n{}\n{}\n{}", sid, challenge, ts_out, manifest_str, arg_str);
    let sig_ok = !pf.is_empty() && crypto::verify_hex(&state.am_pub, msg.as_bytes(), pf);
    details.push(mk("Output Signature (ECDSA-P256)", sig_ok, "AM signature over output invalid"));

    // 2. Freshness: the challenge we issued must be the one bound into the output.
    let fresh = !request.nonce.is_empty() && challenge == request.nonce && sid == request.session_id;
    details.push(mk("Freshness (challenge binding)", fresh, "challenge or session mismatch / replay"));

    // 3. Graph validity ϕ_G.
    let arg_val: Value = serde_json::from_str(arg_str).unwrap_or_else(|_| json!({}));
    details.append(&mut verify_graph(&arg_val, &state.am_pub));

    // 4. Evidence appraisal: RoT-level freshness + reference values.
    let reference: Option<Value> = std::fs::read_to_string(&state.reference_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok());
    details.append(&mut appraise_evidence(&arg_val, sid, &request.nonce, reference.as_ref()));

    let result = produce_trust_decision(details);
    println!(
        "   → {} ({})",
        if result.trusted { "TRUSTED" } else { "NOT TRUSTED" },
        result.explanation
    );
    Ok(warp::reply::json(&VerifyResponse { result }))
}

fn mk(component: &str, ok: bool, err: &str) -> VerificationDetail {
    VerificationDetail {
        component: component.to_string(),
        verified: ok,
        error: if ok { None } else { Some(err.to_string()) },
    }
}

/// Build an immediate not-trusted response for a hard failure.
fn fail_now(component: &str, err: &str) -> warp::reply::Json {
    let result = produce_trust_decision(vec![mk(component, false, err)]);
    warp::reply::json(&VerifyResponse { result })
}

fn with_state(
    state: VState,
) -> impl Filter<Extract = (VState,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || state.clone())
}
