//! Privacy Control Engine (PCE) Library

pub mod policy;
pub mod validators;
pub mod pseudonymization;
pub mod disclosure;
pub mod persistence;
pub mod crypto;

// Re-export main types
pub use policy::{Policy, ComponentPolicy, PolicyRule, ComplianceResult, PolicyViolation};
pub use validators::validate_node;
pub use pseudonymization::{PseudonymManager, PrivacyRisk};
pub use disclosure::{DisclosurePolicy, DisclosureManifest};
pub use persistence::{
    PseudonymStore, PostgresPseudonymStore, InMemoryPseudonymStore,
    PublicKey, PseudonymMapping, ResolvedKey, PersistenceError,
};
pub use crypto::{extract_public_key_from_cert, extract_public_key_from_der_base64};