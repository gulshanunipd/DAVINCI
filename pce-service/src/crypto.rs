//! Cryptographic utilities for certificate parsing and public key extraction

use openssl::x509::X509;
use openssl::pkey::{PKey, Public};
use openssl::hash::{hash, MessageDigest};
use base64::{Engine as _, engine::general_purpose};
use crate::persistence::{PublicKey, PersistenceError, PersistenceResult};
use chrono::Utc;

/// Extract public key from X.509 certificate (PEM format)
pub fn extract_public_key_from_cert(cert_pem: &str) -> PersistenceResult<PublicKey> {
    // Parse certificate
    let cert = X509::from_pem(cert_pem.as_bytes())
        .map_err(|e| PersistenceError::InvalidData(format!("Invalid PEM certificate: {}", e)))?;
    
    // Extract public key
    let pkey = cert.public_key()
        .map_err(|e| PersistenceError::InvalidData(format!("Cannot extract public key: {}", e)))?;
    
    // Convert to DER
    let key_der = pkey.public_key_to_der()
        .map_err(|e| PersistenceError::InvalidData(format!("Cannot encode to DER: {}", e)))?;
    
    // Calculate fingerprint (SHA-256 of DER)
    let fingerprint_bytes = hash(MessageDigest::sha256(), &key_der)
        .map_err(|e| PersistenceError::InvalidData(format!("Cannot hash key: {}", e)))?;
    let key_fingerprint = hex::encode(fingerprint_bytes);
    
    // Detect key type
    let key_type = detect_key_type(&pkey)?;
    
    Ok(PublicKey {
        id: None,
        key_type,
        key_der,
        key_fingerprint,
        source: "Unknown".to_string(), // Will be set by caller
        created_at: Utc::now(),
    })
}

/// Detect public key type and size
fn detect_key_type(pkey: &PKey<Public>) -> PersistenceResult<String> {
    if let Ok(rsa) = pkey.rsa() {
        let bits = rsa.size() * 8;
        return Ok(format!("RSA-{}", bits));
    }
    
    if let Ok(ec) = pkey.ec_key() {
        let group = ec.group();
        let curve_name = group.curve_name()
            .and_then(|nid| nid.short_name().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "Unknown".to_string());
        return Ok(format!("ECDSA-{}", curve_name));
    }
    
    Ok("Unknown".to_string())
}

/// Extract public key from base64-encoded DER certificate
pub fn extract_public_key_from_der_base64(cert_b64: &str) -> PersistenceResult<PublicKey> {
    let der_bytes = general_purpose::STANDARD.decode(cert_b64)
        .map_err(|e| PersistenceError::InvalidData(format!("Invalid base64: {}", e)))?;
    
    let cert = X509::from_der(&der_bytes)
        .map_err(|e| PersistenceError::InvalidData(format!("Invalid DER certificate: {}", e)))?;
    
    let pkey = cert.public_key()
        .map_err(|e| PersistenceError::InvalidData(format!("Cannot extract public key: {}", e)))?;
    
    let key_der = pkey.public_key_to_der()
        .map_err(|e| PersistenceError::InvalidData(format!("Cannot encode to DER: {}", e)))?;
    
    let fingerprint_bytes = hash(MessageDigest::sha256(), &key_der)
        .map_err(|e| PersistenceError::InvalidData(format!("Cannot hash key: {}", e)))?;
    let key_fingerprint = hex::encode(fingerprint_bytes);
    
    let key_type = detect_key_type(&pkey)?;
    
    Ok(PublicKey {
        id: None,
        key_type,
        key_der,
        key_fingerprint,
        source: "Unknown".to_string(),
        created_at: Utc::now(),
    })
}

/// Verify if a string looks like a PEM certificate
pub fn is_pem_certificate(data: &str) -> bool {
    data.trim().starts_with("-----BEGIN CERTIFICATE-----")
}

/// Verify if a string looks like base64-encoded data (heuristic)
pub fn is_base64_encoded(data: &str) -> bool {
    // Simple heuristic: long strings without whitespace, alphanumeric + / =
    if data.len() < 64 {
        return false;
    }
    
    data.chars().all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=')
}

#[cfg(test)]
mod tests {
    use super::*;
    
    const TEST_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIICljCCAX4CCQCKz8Vv3b3UYjANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV
UzAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMA0xCzAJBgNVBAYTAlVT
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw4HvGq7VUvE5RpVTCHOh
-----END CERTIFICATE-----"#;
    
    #[test]
    fn test_is_pem_certificate() {
        assert!(is_pem_certificate(TEST_CERT_PEM));
        assert!(!is_pem_certificate("not a cert"));
    }
    
    #[test]
    fn test_is_base64_encoded() {
        assert!(is_base64_encoded("MIICljCCAX4CCQCKz8Vv3b3UYjANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV"));
        assert!(!is_base64_encoded("short"));
        assert!(!is_base64_encoded("contains spaces in string"));
    }
}
