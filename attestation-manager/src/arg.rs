//! Attestation Record Graph (ARG) implementation
//! 
//! This module provides the graph data structure for representing relationships
//! between attestation evidence nodes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;
use crate::amc::AcmNode;

/// Edge in the attestation graph representing a relationship between nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArgEdge {
    /// Source node ID
    pub from: Uuid,
    
    /// Target node ID
    pub to: Uuid,
    
    /// Type of relationship
    pub relationship: ArgRelationship,
    
    /// Signature over the edge (if applicable)
    pub signature: Option<String>,
}

/// Types of relationships in the attestation graph
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ArgRelationship {
    /// VM attestation includes hypervisor measurement
    VmIncludesHypervisor,

    /// Runtime measurement is linked to boot-time evidence
    RuntimeLinkedToBoot,

    /// vTPM is bound to platform TPM
    VtpmBoundToPtpm,

    /// Policy validation
    PolicyValidates,
}

impl ArgRelationship {
    /// Stable string tag used inside the AM-signed edge message. Must match the
    /// serde variant name so the (separate-crate) verifier reconstructs the same
    /// bytes from the exported ARG JSON.
    pub fn tag(&self) -> &'static str {
        match self {
            ArgRelationship::VmIncludesHypervisor => "VmIncludesHypervisor",
            ArgRelationship::RuntimeLinkedToBoot => "RuntimeLinkedToBoot",
            ArgRelationship::VtpmBoundToPtpm => "VtpmBoundToPtpm",
            ArgRelationship::PolicyValidates => "PolicyValidates",
        }
    }
}

/// Canonical message an AM signs (and the verifier checks) for a trust edge:
/// `from | to | relationship | from_hash | to_hash`. Binding the endpoint node
/// hashes means an edge cannot be re-pointed at substituted evidence without
/// invalidating the AM signature (D3 §5.6 signed edges / §12 Π_bind).
pub fn edge_signing_message(
    from: &Uuid,
    to: &Uuid,
    relationship: &ArgRelationship,
    from_hash: &str,
    to_hash: &str,
) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        from,
        to,
        relationship.tag(),
        from_hash,
        to_hash
    )
}

/// Attestation Record Graph (ARG)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationRecordGraph {
    /// All nodes in the graph
    pub nodes: HashMap<Uuid, AcmNode>,
    
    /// All edges in the graph
    pub edges: Vec<ArgEdge>,
    
    /// Metadata for each node (indexed by node ID)
    pub metadata: HashMap<Uuid, NodeMetadata>,
    
    /// Index for quick lookup of incoming edges
    incoming_edges: HashMap<Uuid, Vec<usize>>,
    
    /// Index for quick lookup of outgoing edges
    outgoing_edges: HashMap<Uuid, Vec<usize>>,
}

impl AttestationRecordGraph {
    /// Create a new empty ARG
    pub fn new() -> Self {
        AttestationRecordGraph {
            nodes: HashMap::new(),
            edges: Vec::new(),
            metadata: HashMap::new(),
            incoming_edges: HashMap::new(),
            outgoing_edges: HashMap::new(),
        }
    }
    
    /// Add a node to the graph
    pub fn add_node(&mut self, node: AcmNode) {
        let node_id = node.jti;
        self.nodes.insert(node_id, node);
        
        // Initialize empty metadata for this node
        self.metadata.insert(node_id, NodeMetadata::new());
    }
    
    /// Add an edge to the graph
    pub fn add_edge(&mut self, edge: ArgEdge) {
        let edge_index = self.edges.len();
        
        // Update indices
        self.incoming_edges
            .entry(edge.to)
            .or_insert_with(Vec::new)
            .push(edge_index);
            
        self.outgoing_edges
            .entry(edge.from)
            .or_insert_with(Vec::new)
            .push(edge_index);
            
        self.edges.push(edge);
    }
    
    /// Get all nodes
    pub fn get_nodes(&self) -> &HashMap<Uuid, AcmNode> {
        &self.nodes
    }
    
    /// Get all edges
    pub fn get_edges(&self) -> &Vec<ArgEdge> {
        &self.edges
    }
    
    /// Get incoming edges for a node
    pub fn get_incoming_edges(&self, node_id: &Uuid) -> Vec<&ArgEdge> {
        if let Some(indices) = self.incoming_edges.get(node_id) {
            indices.iter().map(|&i| &self.edges[i]).collect()
        } else {
            Vec::new()
        }
    }
    
    /// Get outgoing edges for a node
    pub fn get_outgoing_edges(&self, node_id: &Uuid) -> Vec<&ArgEdge> {
        if let Some(indices) = self.outgoing_edges.get(node_id) {
            indices.iter().map(|&i| &self.edges[i]).collect()
        } else {
            Vec::new()
        }
    }
    
    /// Get neighbors of a node (connected nodes)
    pub fn get_neighbors(&self, node_id: &Uuid) -> HashSet<Uuid> {
        let mut neighbors = HashSet::new();
        
        // Add nodes from incoming edges
        if let Some(indices) = self.incoming_edges.get(node_id) {
            for &index in indices {
                neighbors.insert(self.edges[index].from);
            }
        }
        
        // Add nodes from outgoing edges
        if let Some(indices) = self.outgoing_edges.get(node_id) {
            for &index in indices {
                neighbors.insert(self.edges[index].to);
            }
        }
        
        neighbors
    }
    
    /// Verify the integrity of the graph
    pub fn verify_integrity(&self) -> bool {
        // Check that all edges reference existing nodes
        for edge in &self.edges {
            if !self.nodes.contains_key(&edge.from) {
                return false;
            }
            if !self.nodes.contains_key(&edge.to) {
                return false;
            }
        }
        
        true
    }
    
    /// Export the graph as JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
    
    /// Import the graph from JSON
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
    
    /// Set metadata for a node
    pub fn set_node_metadata(&mut self, node_id: Uuid, metadata: NodeMetadata) {
        self.metadata.insert(node_id, metadata);
    }
    
    /// Get metadata for a node
    pub fn get_node_metadata(&self, node_id: &Uuid) -> Option<&NodeMetadata> {
        self.metadata.get(node_id)
    }
    
    /// Update compliance status for a node
    pub fn set_node_compliance(&mut self, node_id: Uuid, compliance: ComplianceStatus) {
        if let Some(metadata) = self.metadata.get_mut(&node_id) {
            metadata.set_compliance(compliance);
        }
    }
    
    /// Find path from a node to the platform layer (for transitive trust)
    pub fn find_path_to_platform(&self, start_node_id: &Uuid) -> Option<Vec<Uuid>> {
        use std::collections::VecDeque;
        
        let start_node = self.nodes.get(start_node_id)?;
        
        // If already platform, return single-node path
        if start_node.layer == crate::amc::Layer::Platform {
            return Some(vec![*start_node_id]);
        }
        
        // BFS to find path to platform
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();
        let mut parent = HashMap::new();
        
        queue.push_back(*start_node_id);
        visited.insert(*start_node_id);
        
        while let Some(current_id) = queue.pop_front() {
            let current_node = self.nodes.get(&current_id)?;
            
            // Check if we reached platform
            if current_node.layer == crate::amc::Layer::Platform {
                // Reconstruct path
                let mut path = Vec::new();
                let mut node = current_id;
                path.push(node);
                
                while let Some(&prev) = parent.get(&node) {
                    path.push(prev);
                    node = prev;
                }
                
                path.reverse();
                return Some(path);
            }
            
            // Explore outgoing edges (going "down" the stack)
            for edge in self.get_outgoing_edges(&current_id) {
                if !visited.contains(&edge.to) {
                    visited.insert(edge.to);
                    parent.insert(edge.to, current_id);
                    queue.push_back(edge.to);
                }
            }
        }
        
        None // No path found
    }
    
    /// Verify transitive trust from a node to platform
    pub fn verify_transitive_trust(&self, node_id: &Uuid) -> bool {
        // Find path to platform
        let path = match self.find_path_to_platform(node_id) {
            Some(p) => p,
            None => return false, // No path means trust broken
        };
        
        // Verify all nodes in path exist and are valid
        for node_id in &path {
            if !self.nodes.contains_key(node_id) {
                return false;
            }
        }
        
        // Verify all edges in path are valid
        for i in 0..path.len() - 1 {
            let from = path[i];
            let to = path[i + 1];
            
            // Check that an edge exists between these nodes
            let has_edge = self.edges.iter().any(|e| e.from == from && e.to == to);
            
            if !has_edge {
                return false;
            }
        }
        
        true
    }
}

/// Metadata associated with a node in the ARG
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeMetadata {
    /// Compliance status from policy validation
    pub compliance: Option<ComplianceStatus>,
    
    /// History of compliance evaluations
    pub compliance_history: Vec<ComplianceStatus>,
    
    /// Timestamp when metadata was last updated
    pub updated_at: DateTime<Utc>,
    
    /// Custom key-value metadata for extensions
    pub custom: HashMap<String, serde_json::Value>,
}

impl NodeMetadata {
    /// Create new empty metadata
    pub fn new() -> Self {
        NodeMetadata {
            compliance: None,
            compliance_history: Vec::new(),
            updated_at: Utc::now(),
            custom: HashMap::new(),
        }
    }
    
    /// Update compliance status
    pub fn set_compliance(&mut self, status: ComplianceStatus) {
        // Archive current status to history
        if let Some(current) = &self.compliance {
            self.compliance_history.push(current.clone());
        }
        
        // Set new status
        self.compliance = Some(status);
        self.updated_at = Utc::now();
    }
}

/// Compliance status from policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceStatus {
    /// Overall result
    pub status: ComplianceResult,
    
    /// List of policy violations (empty if compliant)
    pub violations: Vec<PolicyViolation>,
    
    /// Policy version used for validation
    pub policy_version: String,
    
    /// Timestamp of validation
    pub validated_at: DateTime<Utc>,
}

/// Compliance result enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ComplianceResult {
    /// Fully compliant with policy
    Compliant,
    
    /// Not compliant with policy
    NonCompliant,
    
    /// Validation pending
    Pending,
    
    /// Policy not available for this node type
    Unknown,
}

/// Policy violation details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolation {
    /// Name of the violated rule
    pub rule_name: String,
    
    /// Severity level
    pub severity: String,
    
    /// Human-readable description
    pub description: String,
    
    /// Field that caused the violation
    pub field: Option<String>,
    
    /// Expected value
    pub expected: Option<String>,
    
    /// Actual value received
    pub actual: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amc::{Layer, Mode, Source};
    
    #[test]
    fn test_arg_creation() {
        let mut arg = AttestationRecordGraph::new();
        
        // Create nodes
        let platform_node = AcmNode::new(
            Layer::Platform,
            Mode::BootTime,
            Source::Tpm,
            "platform evidence".to_string(),
            None,
            None,
        );
        
        let hypervisor_node = AcmNode::new(
            Layer::Hypervisor,
            Mode::BootTime,
            Source::Tpm,
            "hypervisor evidence".to_string(),
            None,
            None,
        );
        
        let vm_node = AcmNode::new(
            Layer::Guest,
            Mode::BootTime,
            Source::SevSnp,
            "vm evidence".to_string(),
            None,
            None,
        );
        
        // Add nodes to graph
        arg.add_node(platform_node.clone());
        arg.add_node(hypervisor_node.clone());
        arg.add_node(vm_node.clone());
        
        // Create edges
        let edge1 = ArgEdge {
            from: hypervisor_node.jti,
            to: platform_node.jti,
            relationship: ArgRelationship::VmIncludesHypervisor,
            signature: None,
        };
        
        let edge2 = ArgEdge {
            from: vm_node.jti,
            to: hypervisor_node.jti,
            relationship: ArgRelationship::VmIncludesHypervisor,
            signature: None,
        };
        
        // Add edges to graph
        arg.add_edge(edge1);
        arg.add_edge(edge2);
        
        // Verify integrity
        assert!(arg.verify_integrity());
        
        // Check neighbors
        let vm_neighbors = arg.get_neighbors(&vm_node.jti);
        assert_eq!(vm_neighbors.len(), 1);
        assert!(vm_neighbors.contains(&hypervisor_node.jti));
    }
    
    #[test]
    fn test_arg_metadata() {
        let mut arg = AttestationRecordGraph::new();
        
        // Create nodes
        let node1 = AcmNode::new(
            Layer::Platform,
            Mode::BootTime,
            Source::Tpm,
            "evidence 1".to_string(),
            None,
            None,
        );
        
        let node2 = AcmNode::new(
            Layer::Guest,
            Mode::Runtime,
            Source::SevSnp,
            "evidence 2".to_string(),
            None,
            None,
        );
        
        // Add nodes to graph
        arg.add_node(node1.clone());
        arg.add_node(node2.clone());
        
        // Set metadata
        let mut metadata1 = NodeMetadata::new();
        metadata1.set_compliance(ComplianceStatus {
            status: ComplianceResult::Compliant,
            violations: vec![],
            policy_version: "v1.0".to_string(),
            validated_at: Utc::now(),
        });
        
        arg.set_node_metadata(node1.jti, metadata1.clone());
        
        // Check metadata retrieval
        let retrieved_metadata = arg.get_node_metadata(&node1.jti).unwrap();
        assert_eq!(retrieved_metadata.compliance.as_ref().unwrap().status, ComplianceResult::Compliant);
        
        // Update compliance status
        metadata1.set_compliance(ComplianceStatus {
            status: ComplianceResult::NonCompliant,
            violations: vec![
                PolicyViolation {
                    rule_name: "rule1".to_string(),
                    severity: "high".to_string(),
                    description: "Violation description".to_string(),
                    field: Some("field1".to_string()),
                    expected: Some("value1".to_string()),
                    actual: Some("value2".to_string()),
                },
            ],
            policy_version: "v1.1".to_string(),
            validated_at: Utc::now(),
        });
        
        arg.set_node_metadata(node1.jti, metadata1.clone());
        
        // Check metadata update
        let updated_metadata = arg.get_node_metadata(&node1.jti).unwrap();
        assert_eq!(updated_metadata.compliance.as_ref().unwrap().status, ComplianceResult::NonCompliant);
        assert_eq!(updated_metadata.compliance_history.len(), 1);
    }
    
    #[test]
    fn test_arg_transitive_trust() {
        let mut arg = AttestationRecordGraph::new();
        
        // Create nodes
        let platform_node = AcmNode::new(
            Layer::Platform,
            Mode::BootTime,
            Source::Tpm,
            "platform evidence".to_string(),
            None,
            None,
        );
        
        let hypervisor_node = AcmNode::new(
            Layer::Hypervisor,
            Mode::BootTime,
            Source::Tpm,
            "hypervisor evidence".to_string(),
            None,
            None,
        );
        
        let vm_node = AcmNode::new(
            Layer::Guest,
            Mode::BootTime,
            Source::SevSnp,
            "vm evidence".to_string(),
            None,
            None,
        );
        
        // Add nodes to graph
        arg.add_node(platform_node.clone());
        arg.add_node(hypervisor_node.clone());
        arg.add_node(vm_node.clone());
        
        // Create edges
        let edge1 = ArgEdge {
            from: hypervisor_node.jti,
            to: platform_node.jti,
            relationship: ArgRelationship::VmIncludesHypervisor,
            signature: None,
        };
        
        let edge2 = ArgEdge {
            from: vm_node.jti,
            to: hypervisor_node.jti,
            relationship: ArgRelationship::VmIncludesHypervisor,
            signature: None,
        };
        
        // Add edges to graph
        arg.add_edge(edge1);
        arg.add_edge(edge2);
        
        // Find path from VM to platform
        let path = arg.find_path_to_platform(&vm_node.jti);
        assert!(path.is_some());
        
        let path = path.unwrap();
        assert_eq!(path.len(), 3);
        assert_eq!(path[0], vm_node.jti);
        assert_eq!(path[1], hypervisor_node.jti);
        assert_eq!(path[2], platform_node.jti);
        
        // Verify transitive trust
        assert!(arg.verify_transitive_trust(&vm_node.jti));
        assert!(arg.verify_transitive_trust(&hypervisor_node.jti));
        assert!(arg.verify_transitive_trust(&platform_node.jti));
    }
}