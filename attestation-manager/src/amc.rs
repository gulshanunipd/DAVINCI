//! Abstract Measurement Chain (AMC) implementation
//! 
//! This module provides the core data structures and functions for normalizing
//! attestation evidence into a uniform node format and maintaining a hash chain
//! for tamper evidence.

use serde::{Deserialize, Serialize};
use chrono::Utc;
use uuid::Uuid;

/// Layer in the attestation stack (D3 §4: Platform < Hypervisor < Guest < Application).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
pub enum Layer {
    #[default]
    Platform,
    Hypervisor,
    Guest,
    /// Application/runtime layer (D2 uses "Application" to avoid clashing with the
    /// Runtime measurement mode).
    Application,
}

/// Mode of attestation evidence
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub enum Mode {
    #[default]
    BootTime,
    Runtime,
    Policy,
}

/// Source of attestation evidence (D3 §4 RoT universe R).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub enum Source {
    #[default]
    Tpm,
    SevSnp,
    Tdx,
    Cca,
    /// OP-TEE attestation PTA (Arm TrustZone)
    OpTee,
    Ima,
    Evm,
}

/// Normalized attestation node structure (RFC 9711 EAT formatted)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmNode {
    /// JWT ID / Nonce for this node (RFC 9711 `jti`)
    pub jti: Uuid,
    
    /// EAT Profile context (stores layer, mode, source info)
    pub eat_profile: String,
    
    /// Structured measurements / evidence payload (RFC 9711 `eat_meas`)
    pub eat_meas: String,
    
    /// Timestamp when this node was created (Unix Epoch) (RFC 9711 `iat`)
    pub iat: i64,
    
    /// Hash of the previous node in the chain (DAVINCI DAG Extension)
    pub x_davinci_prev: Option<String>,
    
    /// Signature over the evidence (DAVINCI DAG Extension)
    pub x_davinci_sig: Option<String>,
    
    /// Hash of this node (DAVINCI DAG Extension)
    pub hash: String,
    
    // We keep the original enums internally for routing but skip standard serialization for them
    // to strictly adhere to the flat EAT profile if exported, but here we just leave them explicitly
    // to avoid refactoring the entire engine's logic.
    #[serde(skip, default)]
    pub layer: Layer,
    #[serde(skip, default)]
    pub mode: Mode,
    #[serde(skip, default)]
    pub source: Source,
}

impl AcmNode {
    /// Create a new ACM node
    pub fn new(
        layer: Layer,
        mode: Mode,
        source: Source,
        evidence: String,
        signature: Option<String>,
        previous_hash: Option<String>,
    ) -> Self {
        let jti = Uuid::new_v4();
        let iat = Utc::now().timestamp();
        let eat_profile = format!("layer:{:?},mode:{:?},source:{:?}", layer, mode, source);
        
        // Calculate hash of this node
        let hash = Self::calculate_hash(&jti, &eat_profile, &evidence, &iat, &previous_hash, &signature);
        
        AcmNode {
            jti,
            eat_profile,
            eat_meas: evidence,
            iat,
            x_davinci_prev: previous_hash,
            x_davinci_sig: signature,
            hash,
            layer,
            mode,
            source,
        }
    }
    
    /// Calculate the hash of a node
    fn calculate_hash(
        jti: &Uuid,
        eat_profile: &str,
        eat_meas: &str,
        iat: &i64,
        x_davinci_prev: &Option<String>,
        x_davinci_sig: &Option<String>,
    ) -> String {
        use openssl::hash::{hash, MessageDigest};
        
        let mut data = String::new();
        data.push_str(&jti.to_string());
        data.push_str(eat_profile);
        data.push_str(eat_meas);
        data.push_str(&iat.to_string());
        if let Some(prev) = x_davinci_prev {
            data.push_str(prev);
        }
        if let Some(sig) = x_davinci_sig {
            data.push_str(sig);
        }
        
        let hash_bytes = hash(MessageDigest::sha256(), data.as_bytes()).unwrap();
        hex::encode(hash_bytes)
    }
    
    /// Verify the integrity of this node
    pub fn verify_integrity(&self) -> bool {
        let calculated_hash = Self::calculate_hash(
            &self.jti,
            &self.eat_profile,
            &self.eat_meas,
            &self.iat,
            &self.x_davinci_prev,
            &self.x_davinci_sig,
        );
        
        calculated_hash == self.hash
    }
}

/// AMC chain for maintaining tamper-evident sequence of nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmChain {
    /// List of nodes in the chain
    pub nodes: Vec<AcmNode>,
}

impl AcmChain {
    /// Create a new empty chain
    pub fn new() -> Self {
        AcmChain {
            nodes: Vec::new(),
        }
    }
    
    /// Add a new node to the chain, returning the (possibly re-linked) node so
    /// the caller can store the identical node — same `hash` and `x_davinci_prev`
    /// — in the ARG. This keeps the AMC and ARG views of a node byte-consistent.
    pub fn add_node(&mut self, mut node: AcmNode) -> AcmNode {
        // Set the previous hash to the hash of the last node
        if let Some(last_node) = self.nodes.last() {
            node.x_davinci_prev = Some(last_node.hash.clone());

            // Recalculate hash since previous_hash has changed
            node.hash = AcmNode::calculate_hash(
                &node.jti,
                &node.eat_profile,
                &node.eat_meas,
                &node.iat,
                &node.x_davinci_prev,
                &node.x_davinci_sig,
            );
        }

        self.nodes.push(node.clone());
        node
    }
    
    /// Verify the integrity of the entire chain
    pub fn verify_chain(&self) -> bool {
        for (i, node) in self.nodes.iter().enumerate() {
            // Verify individual node integrity
            if !node.verify_integrity() {
                return false;
            }
            
            // Verify linkage to previous node
            if i > 0 {
                let previous_node = &self.nodes[i - 1];
                if let Some(ref prev_hash) = node.x_davinci_prev {
                    if prev_hash != &previous_node.hash {
                        return false;
                    }
                } else {
                    return false;
                }
            } else {
                // First node should not have a previous hash
                if node.x_davinci_prev.is_some() {
                    return false;
                }
            }
        }
        
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_node_creation() {
        let node = AcmNode::new(
            Layer::Platform,
            Mode::BootTime,
            Source::Tpm,
            "test evidence".to_string(),
            Some("test signature".to_string()),
            None,
        );
        
        assert!(node.verify_integrity());
    }
    
    #[test]
    fn test_chain_integrity() {
        let mut chain = AcmChain::new();
        
        let node1 = AcmNode::new(
            Layer::Platform,
            Mode::BootTime,
            Source::Tpm,
            "platform evidence".to_string(),
            None,
            None,
        );
        
        let node2 = AcmNode::new(
            Layer::Hypervisor,
            Mode::BootTime,
            Source::Tpm,
            "hypervisor evidence".to_string(),
            None,
            Some(node1.hash.clone()),
        );
        
        chain.add_node(node1);
        chain.add_node(node2);
        
        assert!(chain.verify_chain());
    }
}