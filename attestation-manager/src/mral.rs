//! Multi-RoT Abstraction Layer (MRAL) — Collect + Auth (D3 §9).
//!
//! In this prototype the per-source collectors run as external evidence sources
//! (see `mral-adapters/` and the demo drivers), each signing its measurement
//! with a Root-of-Trust key. The security-relevant MRAL operation performed
//! inside the attester is `Auth`: verifying that RoT signature over the
//! measurement before the evidence is admitted to the session evidence set.

use openssl::pkey::{PKey, Public};
use crate::crypto;

/// MRAL `Auth` predicate (D3 Eq. 5): verify that the normalized evidence carries
/// an authentic Root-of-Trust signature over its measurement/timestamp `(µ, ts)`.
///
/// The evidence envelope produced by each source carries:
///   - `measurement`: the RoT measurement digest µ (hex SHA-256)
///   - `ts`: the hardware timestamp (unix seconds)
///   - `rot_sig`: hex(DER) ECDSA-P256 signature by sk_r over the bytes `µ|ts`
///
/// Only evidence with `Auth == 1` may be admitted to E_sid; this is the
/// security gate that D2/D3 place before Transform and Attest.
pub fn verify_rot_auth(
    evidence: &serde_json::Value,
    rot_pub: &PKey<Public>,
) -> Result<(), String> {
    let measurement = evidence
        .get("measurement")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "evidence missing 'measurement' (µ)".to_string())?;
    let ts = evidence
        .get("ts")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| "evidence missing integer 'ts'".to_string())?;
    let rot_sig = evidence
        .get("rot_sig")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "evidence missing 'rot_sig' (RoT signature)".to_string())?;

    // Canonical signed message: exactly what each source signs.
    let msg = format!("{}|{}", measurement, ts);
    if crypto::verify_hex(rot_pub, msg.as_bytes(), rot_sig) {
        Ok(())
    } else {
        Err("RoT signature invalid — evidence not authentic (Auth = 0)".to_string())
    }
}
