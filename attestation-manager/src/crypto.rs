//! ECDSA-P256 signing helpers (D3 Setup/Attest).
//!
//! Instantiates the EUF-CMA(ECDSA-P256) primitive that the DAVINCI security
//! properties rely on (D2 Eq. 51 / D3 §5.1). Signatures are DER-encoded and
//! hex-encoded for JSON transport.
//! The verifier crate mirrors the verification side of this convention.

use openssl::ec::EcKey;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use std::fs;

/// Load an ECDSA-P256 private key (PEM) — the AM signing key sk_AM.
pub fn load_private_key(path: &str) -> Result<PKey<Private>, String> {
    let pem = fs::read(path).map_err(|e| format!("read {}: {}", path, e))?;
    let ec = EcKey::private_key_from_pem(&pem)
        .map_err(|e| format!("parse EC private key {}: {}", path, e))?;
    PKey::from_ec_key(ec).map_err(|e| format!("wrap pkey {}: {}", path, e))
}

/// Sign `msg` with SHA-256/ECDSA-P256; returns hex(DER signature).
pub fn sign_hex(key: &PKey<Private>, msg: &[u8]) -> Result<String, String> {
    let mut signer = Signer::new(MessageDigest::sha256(), key).map_err(|e| e.to_string())?;
    signer.update(msg).map_err(|e| e.to_string())?;
    let sig = signer.sign_to_vec().map_err(|e| e.to_string())?;
    Ok(hex::encode(sig))
}
