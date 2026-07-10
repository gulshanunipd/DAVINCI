//! ECDSA-P256 verification helpers (mirror of the AM crypto module).
//!
//! The Verifier only ever needs public-key operations: it loads the trust
//! anchor τ = pk_AM and checks AM signatures over the exported output and the
//! ARG trust edges (D3 §5.7 Verify).

use openssl::ec::EcKey;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Public};
use openssl::sign::Verifier;
use std::fs;

/// Load an ECDSA-P256 public key (PEM) — the trust anchor pk_AM.
pub fn load_public_key(path: &str) -> Result<PKey<Public>, String> {
    let pem = fs::read(path).map_err(|e| format!("read {}: {}", path, e))?;
    let ec = EcKey::public_key_from_pem(&pem)
        .map_err(|e| format!("parse EC public key {}: {}", path, e))?;
    PKey::from_ec_key(ec).map_err(|e| format!("wrap pkey {}: {}", path, e))
}

/// Verify a hex(DER) SHA-256/ECDSA-P256 signature over `msg`. Never panics.
pub fn verify_hex(key: &PKey<Public>, msg: &[u8], sig_hex: &str) -> bool {
    let sig = match hex::decode(sig_hex) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let mut verifier = match Verifier::new(MessageDigest::sha256(), key) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if verifier.update(msg).is_err() {
        return false;
    }
    verifier.verify(&sig).unwrap_or(false)
}
