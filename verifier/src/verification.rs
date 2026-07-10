//! Verification logic — the concrete DAVINCI `Verify` predicate (D3 §5.7).
//!
//! `Verify(τ,c,out,pf) = ECDSA.verify(pk_AM,out,pf) ∧ out.c==c ∧ ϕ_G(out.G')`.
//! This module implements the graph-validity predicate ϕ_G over the exported
//! ARG JSON: platform-root presence, per-edge AM signature checks, layer
//! monotonicity, acyclicity, root-reachability, and the Π_bind edge policy.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet, VecDeque};
use openssl::pkey::{PKey, Public};
use crate::crypto;

/// Verification result returned to the caller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub trusted: bool,
    pub details: Vec<VerificationDetail>,
    pub explanation: String,
}

/// Per-check verification detail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationDetail {
    pub component: String,
    pub verified: bool,
    pub error: Option<String>,
}

impl VerificationDetail {
    fn ok(component: &str) -> Self {
        VerificationDetail { component: component.to_string(), verified: true, error: None }
    }
    fn fail(component: &str, err: &str) -> Self {
        VerificationDetail {
            component: component.to_string(),
            verified: false,
            error: Some(err.to_string()),
        }
    }
}

/// Layer rank in the trust hierarchy (Platform lowest).
fn layer_rank(layer: &str) -> Option<u8> {
    match layer {
        "Platform" => Some(0),
        "Hypervisor" => Some(1),
        "Guest" => Some(2),
        "Application" | "Runtime" => Some(3),
        _ => None,
    }
}

/// Extract the layer name from an `eat_profile` string like
/// "layer:Platform,mode:BootTime,source:Tpm".
fn parse_layer(eat_profile: &str) -> Option<String> {
    for part in eat_profile.split(',') {
        if let Some(v) = part.trim().strip_prefix("layer:") {
            return Some(v.trim().to_string());
        }
    }
    None
}

/// Π_bind: which (from_layer, to_layer, relationship) edges are admissible.
fn relationship_allowed(from_layer: &str, to_layer: &str, rel: &str) -> bool {
    match rel {
        "VmIncludesHypervisor" => {
            (from_layer == "Hypervisor" && to_layer == "Platform")
                || (from_layer == "Guest" && to_layer == "Hypervisor")
        }
        "RuntimeLinkedToBoot" => {
            (from_layer == "Application" || from_layer == "Runtime") && to_layer == "Guest"
        }
        "VtpmBoundToPtpm" => from_layer == "Guest" && to_layer == "Platform",
        "PolicyValidates" => true,
        _ => false,
    }
}

/// Can `start` reach any node in `targets` following directed edges?
fn reaches(adj: &HashMap<String, Vec<String>>, start: &str, targets: &HashSet<String>) -> bool {
    let mut queue = VecDeque::new();
    let mut visited = HashSet::new();
    queue.push_back(start.to_string());
    visited.insert(start.to_string());
    while let Some(cur) = queue.pop_front() {
        if targets.contains(&cur) {
            return true;
        }
        if let Some(neighbors) = adj.get(&cur) {
            for n in neighbors {
                if visited.insert(n.clone()) {
                    queue.push_back(n.clone());
                }
            }
        }
    }
    false
}

/// DFS cycle detection over the directed adjacency.
fn is_acyclic(adj: &HashMap<String, Vec<String>>) -> bool {
    let mut color: HashMap<String, u8> = HashMap::new(); // 0=white,1=gray,2=black
    fn dfs(
        node: &str,
        adj: &HashMap<String, Vec<String>>,
        color: &mut HashMap<String, u8>,
    ) -> bool {
        color.insert(node.to_string(), 1);
        if let Some(neighbors) = adj.get(node) {
            for n in neighbors {
                match color.get(n).copied().unwrap_or(0) {
                    1 => return false,             // back-edge → cycle
                    0 => {
                        if !dfs(n, adj, color) {
                            return false;
                        }
                    }
                    _ => {}
                }
            }
        }
        color.insert(node.to_string(), 2);
        true
    }
    let keys: Vec<String> = adj.keys().cloned().collect();
    for k in keys {
        if color.get(&k).copied().unwrap_or(0) == 0 && !dfs(&k, adj, &mut color) {
            return false;
        }
    }
    true
}

/// ϕ_G — structural + cryptographic validity of the exported ARG.
pub fn verify_graph(arg: &Value, am_pub: &PKey<Public>) -> Vec<VerificationDetail> {
    let mut details = Vec::new();

    // Index nodes: jti -> layer, jti -> hash.
    let mut node_layer: HashMap<String, String> = HashMap::new();
    let mut node_hash: HashMap<String, String> = HashMap::new();
    if let Some(nodes) = arg.get("nodes").and_then(|v| v.as_object()) {
        for (id, n) in nodes {
            let eat = n.get("eat_profile").and_then(|v| v.as_str()).unwrap_or("");
            let layer = parse_layer(eat).unwrap_or_default();
            let hash = n.get("hash").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let jti = n.get("jti").and_then(|v| v.as_str()).unwrap_or(id).to_string();
            node_layer.insert(jti.clone(), layer);
            node_hash.insert(jti, hash);
        }
    }

    if node_layer.is_empty() {
        details.push(VerificationDetail::fail("ARG Non-Empty", "no attestation nodes present"));
        return details;
    }

    // (i) Platform root exists.
    let has_platform = node_layer.values().any(|l| l == "Platform");
    details.push(if has_platform {
        VerificationDetail::ok("Platform Root Present")
    } else {
        VerificationDetail::fail("Platform Root Present", "no Platform-layer node in ARG")
    });

    // (ii)-(iv) Walk edges: signatures, monotonicity, Π_bind; build adjacency.
    let mut edges_ok = true;
    let mut edges_err: Option<String> = None;
    let mut monotonic_ok = true;
    let mut monotonic_err: Option<String> = None;
    let mut bind_ok = true;
    let mut bind_err: Option<String> = None;
    let mut adj: HashMap<String, Vec<String>> = HashMap::new();

    if let Some(edges) = arg.get("edges").and_then(|v| v.as_array()) {
        for e in edges {
            let from = e.get("from").and_then(|v| v.as_str()).unwrap_or("");
            let to = e.get("to").and_then(|v| v.as_str()).unwrap_or("");
            let rel = e.get("relationship").and_then(|v| v.as_str()).unwrap_or("");
            let sig = e.get("signature").and_then(|v| v.as_str());

            // Edge signature under pk_AM.
            match (node_hash.get(from), node_hash.get(to), sig) {
                (Some(fh), Some(th), Some(sig)) => {
                    let msg = format!("{}|{}|{}|{}|{}", from, to, rel, fh, th);
                    if !crypto::verify_hex(am_pub, msg.as_bytes(), sig) {
                        edges_ok = false;
                        edges_err = Some(format!("invalid AM signature on edge {} → {}", from, to));
                    }
                }
                _ => {
                    edges_ok = false;
                    edges_err = Some(format!("edge {} → {} missing signature or endpoint", from, to));
                }
            }

            // Monotonicity + binding policy.
            match (node_layer.get(from), node_layer.get(to)) {
                (Some(fl), Some(tl)) => {
                    match (layer_rank(fl), layer_rank(tl)) {
                        (Some(fr), Some(tr)) if fr > tr => {}
                        _ => {
                            monotonic_ok = false;
                            monotonic_err = Some(format!("edge {}→{} not layer-monotone", fl, tl));
                        }
                    }
                    if !relationship_allowed(fl, tl, rel) {
                        bind_ok = false;
                        bind_err = Some(format!("edge {}→{} ({}) violates Π_bind", fl, tl, rel));
                    }
                }
                _ => {
                    monotonic_ok = false;
                    bind_ok = false;
                    bind_err = Some("edge references unknown node".to_string());
                }
            }

            adj.entry(from.to_string()).or_default().push(to.to_string());
        }
    }

    details.push(match edges_err {
        Some(e) if !edges_ok => VerificationDetail::fail("Edge Signatures (ECDSA-P256)", &e),
        _ => VerificationDetail::ok("Edge Signatures (ECDSA-P256)"),
    });
    details.push(match monotonic_err {
        Some(e) if !monotonic_ok => VerificationDetail::fail("Layer Monotonicity", &e),
        _ => VerificationDetail::ok("Layer Monotonicity"),
    });
    details.push(match bind_err {
        Some(e) if !bind_ok => VerificationDetail::fail("Binding Policy (Π_bind)", &e),
        _ => VerificationDetail::ok("Binding Policy (Π_bind)"),
    });

    // (v) Acyclicity.
    let acyclic = is_acyclic(&adj);
    details.push(if acyclic {
        VerificationDetail::ok("Acyclicity")
    } else {
        VerificationDetail::fail("Acyclicity", "trust graph contains a cycle")
    });

    // (vi) Cross-layer trust continuity: every non-root node reaches a Platform node.
    let platform_ids: HashSet<String> = node_layer
        .iter()
        .filter(|(_, l)| *l == "Platform")
        .map(|(id, _)| id.clone())
        .collect();
    let mut cltc_ok = true;
    let mut cltc_err: Option<String> = None;
    for (id, layer) in &node_layer {
        if layer == "Platform" {
            continue;
        }
        if !reaches(&adj, id, &platform_ids) {
            cltc_ok = false;
            cltc_err = Some(format!("{}-layer node has no trust path to Platform", layer));
            break;
        }
    }
    details.push(match cltc_err {
        Some(e) if !cltc_ok => VerificationDetail::fail("Cross-Layer Trust Continuity", &e),
        _ => VerificationDetail::ok("Cross-Layer Trust Continuity"),
    });

    details
}

/// Combine all checks into a single trust decision.
pub fn produce_trust_decision(details: Vec<VerificationDetail>) -> VerificationResult {
    let trusted = details.iter().all(|d| d.verified);
    let explanation = if trusted {
        "All attestation checks passed: output signature valid, challenge fresh, and the trust graph is cryptographically and structurally sound. VM is trusted.".to_string()
    } else {
        let failed: Vec<&str> = details
            .iter()
            .filter(|d| !d.verified)
            .map(|d| d.component.as_str())
            .collect();
        format!("Verification failed for: {:?}", failed)
    };
    VerificationResult { trusted, details, explanation }
}
