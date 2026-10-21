//! TPM 2.0 Root of Trust — native verification of TPM structures (D3 §9).
//!
//! Everything the TPM collector returns is checked here; the collector is not
//! trusted. Enrollment establishes trust in an Attestation Key (AK):
//!   1. the EK certificate chains to the TPM manufacturer CA,
//!   2. the AK public area describes a restricted, TPM-resident ECDSA-P256
//!      signing key whose Name matches the claimed one,
//!   3. TPM2_MakeCredential to the certified EK is answered by
//!      TPM2_ActivateCredential, proving the AK lives in that same TPM.
//! Collection then verifies a TPM2_Quote: AK signature over TPMS_ATTEST,
//! qualifying data (nonce), PCR selection, PCR digest, and an event-log replay.

use std::collections::BTreeMap;

use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use openssl::encrypt::Encrypter;
use openssl::hash::{hash, MessageDigest};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Public};
use openssl::rsa::Padding;
use openssl::sign::{Signer, Verifier};
use openssl::stack::Stack;
use openssl::symm::{encrypt, Cipher};
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509StoreContext, X509};

const TPM_GENERATED_VALUE: u32 = 0xff54_4347;
const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;
const TPM_ALG_SHA256: u16 = 0x000b;
const TPM_ALG_ECC: u16 = 0x0023;
const TPM_ALG_ECDSA: u16 = 0x0018;
const TPM_ALG_NULL: u16 = 0x0010;
const TPM_ECC_NIST_P256: u16 = 0x0003;

// TPMA_OBJECT bits
const FIXED_TPM: u32 = 1 << 1;
const FIXED_PARENT: u32 = 1 << 4;
const SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
const RESTRICTED: u32 = 1 << 16;
const DECRYPT: u32 = 1 << 17;
const SIGN: u32 = 1 << 18;

/// Big-endian reader over TPM marshaled structures.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.pos + n > self.buf.len() {
            return Err("truncated TPM structure".into());
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, String> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32, String> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self) -> Result<u64, String> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes(b.try_into().unwrap()))
    }
    /// TPM2B_*: u16 size followed by that many bytes.
    fn tpm2b(&mut self) -> Result<&'a [u8], String> {
        let n = self.u16()? as usize;
        self.take(n)
    }
    fn done(&self) -> bool {
        self.pos == self.buf.len()
    }
}

fn sha256(data: &[u8]) -> Vec<u8> {
    hash(MessageDigest::sha256(), data).unwrap().to_vec()
}

/// A verified-to-be-well-formed AK public area.
#[derive(Debug, Clone)]
pub struct AkPublic {
    /// TPM Name: nameAlg || SHA-256(TPMT_PUBLIC)
    pub name: Vec<u8>,
    pub key: PKey<Public>,
}

/// Parse a TPM2B_PUBLIC holding the AK and enforce the AK key profile:
/// ECC P-256, ECDSA/SHA-256, restricted signing, fixedTPM/fixedParent,
/// generated inside the TPM. A restricted key only signs digests the TPM
/// produced itself, which is what makes a quote unforgeable.
pub fn parse_ak_public(tpm2b_public: &[u8]) -> Result<AkPublic, String> {
    let mut outer = Reader::new(tpm2b_public);
    let tpmt = outer.tpm2b()?;
    if !outer.done() {
        return Err("trailing bytes after TPM2B_PUBLIC".into());
    }
    let mut r = Reader::new(tpmt);
    if r.u16()? != TPM_ALG_ECC {
        return Err("AK is not an ECC key".into());
    }
    if r.u16()? != TPM_ALG_SHA256 {
        return Err("AK nameAlg is not SHA-256".into());
    }
    let attrs = r.u32()?;
    let required = FIXED_TPM | FIXED_PARENT | SENSITIVE_DATA_ORIGIN | RESTRICTED | SIGN;
    if attrs & required != required || attrs & DECRYPT != 0 {
        return Err(format!(
            "AK attributes 0x{:08x} are not a restricted TPM-resident signing key",
            attrs
        ));
    }
    let _auth_policy = r.tpm2b()?;
    // TPMS_ECC_PARMS
    let sym = r.u16()?;
    if sym != TPM_ALG_NULL {
        return Err("AK has a symmetric algorithm (not a signing key)".into());
    }
    if r.u16()? != TPM_ALG_ECDSA || r.u16()? != TPM_ALG_SHA256 {
        return Err("AK scheme is not ECDSA/SHA-256".into());
    }
    if r.u16()? != TPM_ECC_NIST_P256 {
        return Err("AK curve is not NIST P-256".into());
    }
    if r.u16()? != TPM_ALG_NULL {
        return Err("AK has an unexpected KDF".into());
    }
    let x = r.tpm2b()?;
    let y = r.tpm2b()?;
    if !r.done() {
        return Err("trailing bytes after TPMT_PUBLIC".into());
    }

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(|e| e.to_string())?;
    let bx = BigNum::from_slice(x).map_err(|e| e.to_string())?;
    let by = BigNum::from_slice(y).map_err(|e| e.to_string())?;
    let ec = EcKey::from_public_key_affine_coordinates(&group, &bx, &by)
        .map_err(|e| format!("AK point invalid: {}", e))?;
    ec.check_key().map_err(|e| format!("AK point invalid: {}", e))?;

    let mut name = TPM_ALG_SHA256.to_be_bytes().to_vec();
    name.extend(sha256(tpmt));
    Ok(AkPublic { name, key: PKey::from_ec_key(ec).map_err(|e| e.to_string())? })
}

/// Validate the EK certificate against the TPM manufacturer CA and return
/// the certified EK public key (RSA-2048).
pub fn verify_ek_certificate(
    ek_cert_pem: &str,
    root_pem: &[u8],
    intermediate_pem: Option<&[u8]>,
) -> Result<PKey<Public>, String> {
    let cert = X509::from_pem(ek_cert_pem.as_bytes()).map_err(|e| format!("EK cert: {}", e))?;
    let mut store = X509StoreBuilder::new().map_err(|e| e.to_string())?;
    for root in X509::stack_from_pem(root_pem).map_err(|e| format!("root CA: {}", e))? {
        store.add_cert(root).map_err(|e| e.to_string())?;
    }
    let store = store.build();
    let mut chain = Stack::new().map_err(|e| e.to_string())?;
    if let Some(pem) = intermediate_pem {
        for c in X509::stack_from_pem(pem).map_err(|e| format!("issuer CA: {}", e))? {
            chain.push(c).map_err(|e| e.to_string())?;
        }
    }
    let mut ctx = X509StoreContext::new().map_err(|e| e.to_string())?;
    let ok = ctx
        .init(&store, &cert, &chain, |c| {
            let ok = c.verify_cert()?;
            if !ok {
                return Ok(Err(c.error().error_string().to_string()));
            }
            Ok(Ok(()))
        })
        .map_err(|e| e.to_string())?;
    ok.map_err(|e| format!("EK certificate does not chain to the TPM manufacturer CA: {}", e))?;

    let key = cert.public_key().map_err(|e| e.to_string())?;
    let rsa = key.rsa().map_err(|_| "EK is not an RSA key".to_string())?;
    if rsa.size() != 256 {
        return Err("EK is not RSA-2048".into());
    }
    Ok(key)
}

/// TCG KDFa (SP800-108 counter mode, HMAC-SHA256).
fn kdfa(key: &[u8], label: &str, context_u: &[u8], context_v: &[u8], bits: u32) -> Vec<u8> {
    let hmac_key = PKey::hmac(key).unwrap();
    let mut out = Vec::new();
    let mut counter: u32 = 1;
    while out.len() * 8 < bits as usize {
        let mut s = Signer::new(MessageDigest::sha256(), &hmac_key).unwrap();
        s.update(&counter.to_be_bytes()).unwrap();
        s.update(label.as_bytes()).unwrap();
        s.update(&[0]).unwrap();
        s.update(context_u).unwrap();
        s.update(context_v).unwrap();
        s.update(&bits.to_be_bytes()).unwrap();
        out.extend(s.sign_to_vec().unwrap());
        counter += 1;
    }
    out.truncate(bits as usize / 8);
    out
}

/// TPM2_MakeCredential computed by the verifier side, for an RSA-2048 EK with
/// the default EK template (SHA-256 nameAlg, AES-128-CFB storage symmetric).
/// Returns the contents of TPM2B_ID_OBJECT and TPM2B_ENCRYPTED_SECRET. Only
/// the TPM holding the EK private key, with the object `ak_name` loaded, can
/// recover `credential` from them.
pub fn make_credential(
    ek: &PKey<Public>,
    ak_name: &[u8],
    credential: &[u8],
    seed: &[u8; 32],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    // Seed protected to the EK: RSA-OAEP(SHA-256, label "IDENTITY\0").
    let mut enc = Encrypter::new(ek).map_err(|e| e.to_string())?;
    enc.set_rsa_padding(Padding::PKCS1_OAEP).map_err(|e| e.to_string())?;
    enc.set_rsa_oaep_md(MessageDigest::sha256()).map_err(|e| e.to_string())?;
    enc.set_rsa_mgf1_md(MessageDigest::sha256()).map_err(|e| e.to_string())?;
    enc.set_rsa_oaep_label(b"IDENTITY\0").map_err(|e| e.to_string())?;
    let mut enc_seed = vec![0u8; enc.encrypt_len(seed).map_err(|e| e.to_string())?];
    let n = enc.encrypt(seed, &mut enc_seed).map_err(|e| e.to_string())?;
    enc_seed.truncate(n);

    // Credential (as TPM2B_DIGEST) encrypted under the storage key.
    let sym_key = kdfa(seed, "STORAGE", ak_name, &[], 128);
    let mut cv = (credential.len() as u16).to_be_bytes().to_vec();
    cv.extend_from_slice(credential);
    let enc_identity =
        encrypt(Cipher::aes_128_cfb128(), &sym_key, Some(&[0u8; 16]), &cv).map_err(|e| e.to_string())?;

    // Outer integrity HMAC binds the blob to the AK name.
    let hmac_key = kdfa(seed, "INTEGRITY", &[], &[], 256);
    let pk = PKey::hmac(&hmac_key).map_err(|e| e.to_string())?;
    let mut s = Signer::new(MessageDigest::sha256(), &pk).map_err(|e| e.to_string())?;
    s.update(&enc_identity).map_err(|e| e.to_string())?;
    s.update(ak_name).map_err(|e| e.to_string())?;
    let outer_hmac = s.sign_to_vec().map_err(|e| e.to_string())?;

    let mut id_object = (outer_hmac.len() as u16).to_be_bytes().to_vec();
    id_object.extend(outer_hmac);
    id_object.extend(enc_identity);
    Ok((id_object, enc_seed))
}

/// Decoded TPMS_ATTEST of a quote.
#[derive(Debug, Clone)]
pub struct QuoteInfo {
    pub qualified_signer: Vec<u8>,
    pub extra_data: Vec<u8>,
    pub clock: u64,
    pub reset_count: u32,
    pub restart_count: u32,
    pub safe: bool,
    pub firmware_version: u64,
    /// Selected SHA-256 PCR indices, ascending.
    pub pcrs: Vec<u32>,
    pub pcr_digest: Vec<u8>,
}

pub fn parse_quote(attest: &[u8]) -> Result<QuoteInfo, String> {
    let mut r = Reader::new(attest);
    if r.u32()? != TPM_GENERATED_VALUE {
        return Err("attest magic is not TPM_GENERATED_VALUE".into());
    }
    if r.u16()? != TPM_ST_ATTEST_QUOTE {
        return Err("attest is not a quote".into());
    }
    let qualified_signer = r.tpm2b()?.to_vec();
    let extra_data = r.tpm2b()?.to_vec();
    let clock = r.u64()?;
    let reset_count = r.u32()?;
    let restart_count = r.u32()?;
    let safe = r.u8()? != 0;
    let firmware_version = r.u64()?;
    let mut pcrs = Vec::new();
    for _ in 0..r.u32()? {
        let alg = r.u16()?;
        let size = r.u8()? as usize;
        let bitmap = r.take(size)?;
        if alg != TPM_ALG_SHA256 {
            return Err("quote selects a non-SHA-256 PCR bank".into());
        }
        for (byte, bits) in bitmap.iter().enumerate() {
            for bit in 0..8 {
                if bits & (1 << bit) != 0 {
                    pcrs.push((byte * 8 + bit) as u32);
                }
            }
        }
    }
    let pcr_digest = r.tpm2b()?.to_vec();
    if !r.done() {
        return Err("trailing bytes after TPMS_ATTEST".into());
    }
    Ok(QuoteInfo {
        qualified_signer,
        extra_data,
        clock,
        reset_count,
        restart_count,
        safe,
        firmware_version,
        pcrs,
        pcr_digest,
    })
}

/// Verify a TPMT_SIGNATURE (ECDSA/SHA-256) over TPMS_ATTEST with the AK.
pub fn verify_quote_signature(ak: &PKey<Public>, attest: &[u8], tpmt_sig: &[u8]) -> Result<(), String> {
    let mut r = Reader::new(tpmt_sig);
    if r.u16()? != TPM_ALG_ECDSA || r.u16()? != TPM_ALG_SHA256 {
        return Err("quote signature is not ECDSA/SHA-256".into());
    }
    let sig_r = BigNum::from_slice(r.tpm2b()?).map_err(|e| e.to_string())?;
    let sig_s = BigNum::from_slice(r.tpm2b()?).map_err(|e| e.to_string())?;
    let der = EcdsaSig::from_private_components(sig_r, sig_s)
        .and_then(|s| s.to_der())
        .map_err(|e| e.to_string())?;
    let mut v = Verifier::new(MessageDigest::sha256(), ak).map_err(|e| e.to_string())?;
    v.update(attest).map_err(|e| e.to_string())?;
    if v.verify(&der).unwrap_or(false) {
        Ok(())
    } else {
        Err("quote signature does not verify under the enrolled AK".into())
    }
}

/// One measured-boot event (TCG event-log entry, SHA-256 bank).
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Event {
    pub pcr: u32,
    #[serde(rename = "type")]
    pub event_type: String,
    pub description: String,
    pub digest: EventDigest,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct EventDigest {
    pub sha256: String,
}

/// Replay an event log from PCR reset (all zero) and return the PCR values.
pub fn replay_event_log(events: &[Event]) -> Result<BTreeMap<u32, Vec<u8>>, String> {
    let mut pcrs: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    for e in events {
        let d = hex::decode(&e.digest.sha256).map_err(|_| "event digest not hex".to_string())?;
        if d.len() != 32 {
            return Err("event digest is not SHA-256".into());
        }
        let cur = pcrs.entry(e.pcr).or_insert_with(|| vec![0u8; 32]);
        let mut buf = cur.clone();
        buf.extend(d);
        *cur = sha256(&buf);
    }
    Ok(pcrs)
}

/// Full quote appraisal against the enrolled AK. `pcr_values` are the values
/// the collector reported; they are only accepted if they hash to the
/// TPM-signed PCR digest, and the event log is only accepted if it replays to
/// exactly those values.
pub fn verify_quote(
    ak: &PKey<Public>,
    attest: &[u8],
    tpmt_sig: &[u8],
    expected_nonce: &[u8],
    expected_pcrs: &[u32],
    pcr_values: &BTreeMap<u32, Vec<u8>>,
    events: &[Event],
) -> Result<QuoteInfo, String> {
    verify_quote_signature(ak, attest, tpmt_sig)?;
    let q = parse_quote(attest)?;
    if q.extra_data != expected_nonce {
        return Err("quote qualifying data does not match the challenge (stale or replayed)".into());
    }
    if q.pcrs != expected_pcrs {
        return Err(format!("quote covers PCRs {:?}, expected {:?}", q.pcrs, expected_pcrs));
    }
    let mut concat = Vec::new();
    for i in &q.pcrs {
        let v = pcr_values
            .get(i)
            .ok_or_else(|| format!("collector did not report PCR {}", i))?;
        if v.len() != 32 {
            return Err(format!("PCR {} is not a SHA-256 value", i));
        }
        concat.extend(v);
    }
    if sha256(&concat) != q.pcr_digest {
        return Err("reported PCR values do not match the TPM-signed PCR digest".into());
    }
    let replayed = replay_event_log(events)?;
    for i in &q.pcrs {
        let expect = replayed.get(i).cloned().unwrap_or_else(|| vec![0u8; 32]);
        if &expect != pcr_values.get(i).unwrap() {
            return Err(format!("event log does not replay to the quoted PCR {}", i));
        }
    }
    Ok(q)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TCG test vector style check: KDFa output length and determinism.
    #[test]
    fn kdfa_is_deterministic_and_sized() {
        let a = kdfa(b"seed", "STORAGE", b"name", &[], 128);
        let b = kdfa(b"seed", "STORAGE", b"name", &[], 128);
        assert_eq!(a.len(), 16);
        assert_eq!(a, b);
        assert_ne!(a, kdfa(b"seed", "INTEGRITY", b"name", &[], 128));
        assert_eq!(kdfa(b"seed", "INTEGRITY", &[], &[], 256).len(), 32);
    }

    #[test]
    fn replay_matches_manual_extend() {
        let d = "11".repeat(32);
        let ev = vec![Event {
            pcr: 4,
            event_type: "EV_IPL".into(),
            description: "x".into(),
            digest: EventDigest { sha256: d.clone() },
        }];
        let mut buf = vec![0u8; 32];
        buf.extend(hex::decode(d).unwrap());
        assert_eq!(replay_event_log(&ev).unwrap()[&4], sha256(&buf));
    }
}
