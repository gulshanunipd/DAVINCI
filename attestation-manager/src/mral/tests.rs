//! MRAL tests on real evidence captured from the DAVINCI platform
//! (`tests/fixtures/rot-evidence.json`: swtpm EK/AK + quote, OP-TEE PTA
//! output, all bound to the same nonce). Every negative test alters one
//! element an attacker controls and checks that Auth rejects it.

use std::collections::BTreeMap;

use openssl::asn1::Asn1Time;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Public};
use openssl::rsa::Rsa;
use openssl::x509::{X509Builder, X509NameBuilder};
use serde_json::Value;

use super::{optee, qualifying_data, tpm};

const QUOTED: [u32; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

fn fixture() -> Value {
    serde_json::from_str(include_str!("../../tests/fixtures/rot-evidence.json")).unwrap()
}

fn s<'a>(v: &'a Value, path: &[&str]) -> &'a str {
    let mut cur = v;
    for p in path {
        cur = &cur[*p];
    }
    cur.as_str().unwrap()
}

fn h(v: &Value, path: &[&str]) -> Vec<u8> {
    hex::decode(s(v, path)).unwrap()
}

fn pcrs(fx: &Value) -> BTreeMap<u32, Vec<u8>> {
    fx["tpm"]["pcrs"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.parse().unwrap(), hex::decode(v.as_str().unwrap()).unwrap()))
        .collect()
}

fn events(fx: &Value) -> Vec<tpm::Event> {
    serde_json::from_value(fx["tpm"]["event_log"].clone()).unwrap()
}

fn ak(fx: &Value) -> PKey<Public> {
    tpm::parse_ak_public(&h(fx, &["tpm", "ak_public"])).unwrap().key
}

fn verify(fx: &Value, attest: &[u8], nonce: &[u8], p: &BTreeMap<u32, Vec<u8>>, ev: &[tpm::Event]) -> Result<tpm::QuoteInfo, String> {
    tpm::verify_quote(&ak(fx), attest, &h(fx, &["tpm", "signature"]), nonce, &QUOTED, p, ev)
}

#[test]
fn qualifying_data_matches_the_verifier_formula() {
    assert_eq!(
        hex::encode(qualifying_data("tpm", "s1", "abc")),
        "df4bba9d12a8220431b2b227e407ef062065d1f91d4cbec6d3bda4a8f853184d"
    );
}

// ------------------------------------------------------------------ TPM

#[test]
fn ek_certificate_chains_to_manufacturer_ca() {
    let fx = fixture();
    let ek = tpm::verify_ek_certificate(
        s(&fx, &["tpm", "ek_cert"]),
        s(&fx, &["tpm", "root_ca"]).as_bytes(),
        Some(s(&fx, &["tpm", "issuer_ca"]).as_bytes()),
    )
    .unwrap();
    assert_eq!(ek.rsa().unwrap().size(), 256);
}

#[test]
fn ek_certificate_rejected_under_unknown_ca() {
    let fx = fixture();
    // A self-signed CA the platform's EK was never certified by.
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "rogue-manufacturer").unwrap();
    let name = name.build();
    let mut b = X509Builder::new().unwrap();
    b.set_version(2).unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    b.set_not_after(&Asn1Time::days_from_now(1).unwrap()).unwrap();
    b.sign(&key, MessageDigest::sha256()).unwrap();
    let rogue = b.build().to_pem().unwrap();

    let err = tpm::verify_ek_certificate(s(&fx, &["tpm", "ek_cert"]), &rogue, None).unwrap_err();
    assert!(err.contains("does not chain"), "{}", err);
}

#[test]
fn ak_public_parses_and_name_matches() {
    let fx = fixture();
    let ak = tpm::parse_ak_public(&h(&fx, &["tpm", "ak_public"])).unwrap();
    assert_eq!(ak.name, h(&fx, &["tpm", "ak_name"]));
}

#[test]
fn ak_without_restricted_attribute_is_refused() {
    let fx = fixture();
    let mut public = h(&fx, &["tpm", "ak_public"]);
    // TPM2B size(2) | type(2) | nameAlg(2) | objectAttributes(4): clear `restricted` (bit 16).
    public[7] &= !0x01;
    let err = tpm::parse_ak_public(&public).unwrap_err();
    assert!(err.contains("restricted"), "{}", err);
}

#[test]
fn make_credential_produces_tpm_sized_blobs() {
    let fx = fixture();
    let ek = tpm::verify_ek_certificate(
        s(&fx, &["tpm", "ek_cert"]),
        s(&fx, &["tpm", "root_ca"]).as_bytes(),
        Some(s(&fx, &["tpm", "issuer_ca"]).as_bytes()),
    )
    .unwrap();
    let name = h(&fx, &["tpm", "ak_name"]);
    let (id, secret) = tpm::make_credential(&ek, &name, &[7u8; 32], &[9u8; 32]).unwrap();
    // u16 | HMAC-SHA256 | AES-CFB(u16 | 32-byte credential)
    assert_eq!(id.len(), 2 + 32 + 2 + 32);
    assert_eq!(secret.len(), 256);
}

#[test]
fn genuine_quote_verifies() {
    let fx = fixture();
    let q = verify(&fx, &h(&fx, &["tpm", "attest"]), &h(&fx, &["nonce"]), &pcrs(&fx), &events(&fx)).unwrap();
    assert_eq!(q.pcrs, QUOTED.to_vec());
}

#[test]
fn quote_for_another_challenge_is_rejected() {
    let fx = fixture();
    let err = verify(&fx, &h(&fx, &["tpm", "attest"]), &[0u8; 32], &pcrs(&fx), &events(&fx)).unwrap_err();
    assert!(err.contains("qualifying data"), "{}", err);
}

#[test]
fn modified_quote_body_is_rejected() {
    let fx = fixture();
    let mut attest = h(&fx, &["tpm", "attest"]);
    let last = attest.len() - 1;
    attest[last] ^= 0x01; // tamper with the PCR digest
    let err = verify(&fx, &attest, &h(&fx, &["nonce"]), &pcrs(&fx), &events(&fx)).unwrap_err();
    assert!(err.contains("signature"), "{}", err);
}

#[test]
fn forged_pcr_value_is_rejected() {
    let fx = fixture();
    let mut p = pcrs(&fx);
    p.get_mut(&9).unwrap()[0] ^= 0xff; // claim a different initramfs
    let err = verify(&fx, &h(&fx, &["tpm", "attest"]), &h(&fx, &["nonce"]), &p, &events(&fx)).unwrap_err();
    assert!(err.contains("PCR digest"), "{}", err);
}

#[test]
fn forged_event_log_is_rejected() {
    let fx = fixture();
    let mut ev = events(&fx);
    let last = ev.len() - 1;
    ev[last].digest.sha256 = "00".repeat(32); // hide the real initramfs measurement
    let err = verify(&fx, &h(&fx, &["tpm", "attest"]), &h(&fx, &["nonce"]), &pcrs(&fx), &ev).unwrap_err();
    assert!(err.contains("event log"), "{}", err);
}

#[test]
fn quote_signed_by_another_key_is_rejected() {
    let fx = fixture();
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let other = EcKey::generate(&group).unwrap();
    let other_pub = PKey::from_ec_key(EcKey::from_public_key(&group, other.public_key()).unwrap()).unwrap();
    let err = tpm::verify_quote(
        &other_pub,
        &h(&fx, &["tpm", "attest"]),
        &h(&fx, &["tpm", "signature"]),
        &h(&fx, &["nonce"]),
        &QUOTED,
        &pcrs(&fx),
        &events(&fx),
    )
    .unwrap_err();
    assert!(err.contains("enrolled AK"), "{}", err);
}

// --------------------------------------------------------------- OP-TEE

fn optee_key(fx: &Value) -> PKey<Public> {
    optee::public_key(s(fx, &["optee", "e"]), s(fx, &["optee", "n"])).unwrap()
}

#[test]
fn genuine_optee_measurements_verify() {
    let fx = fixture();
    let key = optee_key(&fx);
    let nonce = h(&fx, &["nonce"]);
    for part in ["tee_core", "ta_memory", "ta_shdr"] {
        optee::verify_measurement(
            &key,
            &nonce,
            s(&fx, &["optee", "attest", part, "hash"]),
            s(&fx, &["optee", "attest", part, "sig"]),
        )
        .unwrap();
    }
}

#[test]
fn optee_evidence_for_another_nonce_is_rejected() {
    let fx = fixture();
    let err = optee::verify_measurement(
        &optee_key(&fx),
        b"other-challenge",
        s(&fx, &["optee", "attest", "ta_memory", "hash"]),
        s(&fx, &["optee", "attest", "ta_memory", "sig"]),
    )
    .unwrap_err();
    assert!(err.contains("does not verify"), "{}", err);
}

#[test]
fn substituted_ta_hash_is_rejected() {
    let fx = fixture();
    // Present the TEE-core hash as if it were the TA hash, with the TA signature.
    let err = optee::verify_measurement(
        &optee_key(&fx),
        &h(&fx, &["nonce"]),
        s(&fx, &["optee", "attest", "tee_core", "hash"]),
        s(&fx, &["optee", "attest", "ta_memory", "sig"]),
    )
    .unwrap_err();
    assert!(err.contains("does not verify"), "{}", err);
}

#[test]
fn optee_evidence_under_another_key_is_rejected() {
    let fx = fixture();
    let rogue = Rsa::generate(3072).unwrap();
    let rogue_pub = optee::public_key(
        &hex::encode(rogue.e().to_vec()),
        &hex::encode(rogue.n().to_vec()),
    )
    .unwrap();
    let err = optee::verify_measurement(
        &rogue_pub,
        &h(&fx, &["nonce"]),
        s(&fx, &["optee", "attest", "tee_core", "hash"]),
        s(&fx, &["optee", "attest", "tee_core", "sig"]),
    )
    .unwrap_err();
    assert!(err.contains("does not verify"), "{}", err);
}
