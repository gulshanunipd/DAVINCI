//! OP-TEE (Arm TrustZone) Root of Trust — verification of attestation PTA
//! evidence (D3 §9).
//!
//! The OP-TEE attestation PTA signs runtime measurements with a device RSA key
//! held in OP-TEE secure storage:
//!   out = hash (32 bytes) || RSASSA-PSS-SHA256(SHA-256(nonce || hash)), salt 32
//! for the TEE core memory, the calling TA's memory and the TA signed header.

use openssl::bn::BigNum;
use openssl::hash::{hash, MessageDigest};
use openssl::pkey::{PKey, Public};
use openssl::rsa::{Padding, Rsa};
use openssl::sign::{RsaPssSaltlen, Verifier};

/// TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256 — the only algorithm the PTA uses.
pub const PTA_SIG_ALG: &str = "0x70414930";

/// Rebuild the PTA attestation public key from its big-endian (e, n).
pub fn public_key(e_hex: &str, n_hex: &str) -> Result<PKey<Public>, String> {
    let e = BigNum::from_slice(&hex::decode(e_hex).map_err(|_| "e not hex")?).map_err(|e| e.to_string())?;
    let n = BigNum::from_slice(&hex::decode(n_hex).map_err(|_| "n not hex")?).map_err(|e| e.to_string())?;
    let rsa = Rsa::from_public_components(n, e).map_err(|e| e.to_string())?;
    if rsa.size() < 256 {
        return Err("OP-TEE attestation key shorter than 2048 bits".into());
    }
    PKey::from_rsa(rsa).map_err(|e| e.to_string())
}

/// Fingerprint of the attestation key (SHA-256 of the modulus): a stable
/// device identifier, pseudonymized by the PCE before export.
pub fn key_fingerprint(n_hex: &str) -> String {
    let n = hex::decode(n_hex).unwrap_or_default();
    hex::encode(hash(MessageDigest::sha256(), &n).unwrap())
}

/// Verify one PTA output: signature over (nonce || hash).
pub fn verify_measurement(
    key: &PKey<Public>,
    nonce: &[u8],
    hash_hex: &str,
    sig_hex: &str,
) -> Result<(), String> {
    let digest = hex::decode(hash_hex).map_err(|_| "hash not hex".to_string())?;
    if digest.len() != 32 {
        return Err("measurement is not a SHA-256 hash".into());
    }
    let sig = hex::decode(sig_hex).map_err(|_| "signature not hex".to_string())?;
    let mut v = Verifier::new(MessageDigest::sha256(), key).map_err(|e| e.to_string())?;
    v.set_rsa_padding(Padding::PKCS1_PSS).map_err(|e| e.to_string())?;
    v.set_rsa_pss_saltlen(RsaPssSaltlen::custom(32)).map_err(|e| e.to_string())?;
    v.set_rsa_mgf1_md(MessageDigest::sha256()).map_err(|e| e.to_string())?;
    v.update(nonce).map_err(|e| e.to_string())?;
    v.update(&digest).map_err(|e| e.to_string())?;
    if v.verify(&sig).unwrap_or(false) {
        Ok(())
    } else {
        Err("PTA signature does not verify under the enrolled OP-TEE attestation key".into())
    }
}
