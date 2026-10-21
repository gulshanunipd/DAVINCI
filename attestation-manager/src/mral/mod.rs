//! Multi-RoT Abstraction Layer (MRAL) — Collect + Auth (D3 §9).
//!
//! The MRAL is the only part of the Attestation Manager that talks to Roots of
//! Trust. For every configured RoT it calls that RoT's collector on the
//! attested platform (`mral-adapters/`), verifies the returned evidence
//! natively (`tpm.rs`, `optee.rs`) and normalizes it into per-layer evidence
//! for the Transform (PCE) and Attest (AMC/ARG) stages.
//!
//! Two heterogeneous, real RoTs are supported:
//!   * TPM 2.0 (swtpm) — measured boot of the platform firmware (PCR 0–7,
//!     Platform layer) and of the normal-world kernel (PCR 8–9, Hypervisor).
//!   * OP-TEE / Arm TrustZone — runtime measurement of the TEE OS (Guest
//!     layer) and of the TEE-resident workload TA (Application layer).
//!
//! Trust in each RoT key is established once at enrollment (`enroll`) and
//! persisted; collection (`collect`) binds every RoT signature to the
//! verifier challenge through RoT-specific qualifying data.

pub mod optee;
pub mod tpm;
#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::fs;
use std::sync::Mutex;

use chrono::Utc;
use openssl::hash::{hash, MessageDigest};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::amc::{Layer, Mode, Source};
use crate::arg::ArgRelationship;

/// PCRs quoted on every collection, and how they split across layers.
const QUOTED_PCRS: [u32; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
const PLATFORM_PCRS: std::ops::RangeInclusive<u32> = 0..=7;
const HYPERVISOR_PCRS: std::ops::RangeInclusive<u32> = 8..=9;
/// UUID of the attested OP-TEE workload TA (mral-adapters/optee-adapter/ta).
const WORKLOAD_TA_UUID: &str = "3ef86ac2-55b2-4243-810a-33347fcd1d5d";

/// Qualifying data a RoT must sign: H("DAVINCI" | rot | sid | challenge).
/// The verifier recomputes it from its own challenge, so freshness holds end
/// to end from the RoT signature to the trust decision.
pub fn qualifying_data(rot: &str, session_id: &str, challenge: &str) -> Vec<u8> {
    let msg = format!("DAVINCI|{}|{}|{}", rot, session_id, challenge);
    hash(MessageDigest::sha256(), msg.as_bytes()).unwrap().to_vec()
}

#[derive(Debug, Clone)]
pub struct MralConfig {
    pub tpm_url: String,
    pub optee_url: String,
    /// Directory holding the TPM manufacturer CA (tpm-manufacturer-*.pem).
    pub trust_dir: String,
    /// Enrollment store (trusted AK / PTA key).
    pub store_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmEnrollment {
    /// TPM2B_PUBLIC of the AK (hex) — re-validated on load.
    pub ak_public: String,
    pub ak_name: String,
    pub ek_cert_sha256: String,
    pub enrolled_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpteeEnrollment {
    pub e: String,
    pub n: String,
    pub fingerprint: String,
    pub enrolled_at: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Enrollment {
    pub tpm: Option<TpmEnrollment>,
    pub optee: Option<OpteeEnrollment>,
}

/// Outcome of collecting + verifying one RoT.
#[derive(Debug, Clone, Serialize)]
pub struct RotReport {
    pub rot: String,
    pub verified: bool,
    pub checks: Vec<String>,
    pub error: Option<String>,
}

/// Verified, normalized evidence for one layer, ready for Transform/Attest.
#[derive(Debug, Clone)]
pub struct CollectedNode {
    pub layer: Layer,
    pub mode: Mode,
    pub source: Source,
    pub evidence: Value,
    /// Parent layer in the trust graph and the edge relationship to it.
    pub parent: Option<(Layer, ArgRelationship)>,
}

pub struct Mral {
    cfg: MralConfig,
    client: reqwest::Client,
    enrollment: Mutex<Enrollment>,
}

async fn get_json(client: &reqwest::Client, url: &str) -> Result<Value, String> {
    let v: Value = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("collector unreachable ({}): {}", url, e))?
        .json()
        .await
        .map_err(|e| format!("collector returned invalid JSON: {}", e))?;
    if let Some(err) = v.get("error") {
        return Err(format!("collector error: {}", err));
    }
    Ok(v)
}

fn field<'a>(v: &'a Value, name: &str) -> Result<&'a str, String> {
    v.get(name)
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("collector response missing '{}'", name))
}

fn unhex(v: &Value, name: &str) -> Result<Vec<u8>, String> {
    hex::decode(field(v, name)?).map_err(|_| format!("'{}' is not hex", name))
}

impl Mral {
    pub fn new(cfg: MralConfig) -> Self {
        let enrollment = fs::read_to_string(&cfg.store_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        Mral { cfg, client: reqwest::Client::new(), enrollment: Mutex::new(enrollment) }
    }

    pub fn config(&self) -> &MralConfig {
        &self.cfg
    }

    pub fn enrollment(&self) -> Enrollment {
        self.enrollment.lock().unwrap().clone()
    }

    fn save(&self, e: &Enrollment) -> Result<(), String> {
        let s = serde_json::to_string_pretty(e).unwrap();
        fs::write(&self.cfg.store_path, s).map_err(|err| format!("write {}: {}", self.cfg.store_path, err))
    }

    // ------------------------------------------------------------ enrollment

    /// Enroll every RoT. Each RoT is enrolled independently; the result
    /// reports success or the reason for failure per RoT.
    pub async fn enroll(&self) -> Vec<RotReport> {
        let mut reports = Vec::new();
        let mut current = self.enrollment();

        match self.enroll_tpm().await {
            Ok((e, checks)) => {
                current.tpm = Some(e);
                reports.push(RotReport { rot: "tpm".into(), verified: true, checks, error: None });
            }
            Err(err) => reports.push(RotReport { rot: "tpm".into(), verified: false, checks: vec![], error: Some(err) }),
        }
        match self.enroll_optee().await {
            Ok((e, checks)) => {
                current.optee = Some(e);
                reports.push(RotReport { rot: "optee".into(), verified: true, checks, error: None });
            }
            Err(err) => reports.push(RotReport { rot: "optee".into(), verified: false, checks: vec![], error: Some(err) }),
        }

        if let Err(err) = self.save(&current) {
            reports.push(RotReport { rot: "store".into(), verified: false, checks: vec![], error: Some(err) });
        }
        *self.enrollment.lock().unwrap() = current;
        reports
    }

    async fn enroll_tpm(&self) -> Result<(TpmEnrollment, Vec<String>), String> {
        let base = self.cfg.tpm_url.trim_end_matches('/');
        let info = get_json(&self.client, &format!("{}/enroll", base)).await?;
        let mut checks = Vec::new();

        let root = fs::read(format!("{}/tpm-manufacturer-root.pem", self.cfg.trust_dir))
            .map_err(|e| format!("TPM manufacturer root CA not provisioned in {}: {}", self.cfg.trust_dir, e))?;
        let issuer = fs::read(format!("{}/tpm-manufacturer-issuer.pem", self.cfg.trust_dir)).ok();
        let ek_cert = field(&info, "ek_cert")?;
        let ek = tpm::verify_ek_certificate(ek_cert, &root, issuer.as_deref())?;
        checks.push("EK certificate chains to the TPM manufacturer CA".into());

        let ak = tpm::parse_ak_public(&unhex(&info, "ak_public")?)?;
        if ak.name != unhex(&info, "ak_name")? {
            return Err("AK name does not match its public area".into());
        }
        checks.push("AK is a restricted, fixedTPM ECDSA-P256 signing key; Name recomputed".into());

        let mut credential = [0u8; 32];
        let mut seed = [0u8; 32];
        openssl::rand::rand_bytes(&mut credential).map_err(|e| e.to_string())?;
        openssl::rand::rand_bytes(&mut seed).map_err(|e| e.to_string())?;
        let (id_object, enc_secret) = tpm::make_credential(&ek, &ak.name, &credential, &seed)?;
        let resp: Value = self
            .client
            .post(format!("{}/activate", base))
            .json(&json!({ "id_object": hex::encode(id_object), "encrypted_secret": hex::encode(enc_secret) }))
            .send()
            .await
            .map_err(|e| format!("activate request failed: {}", e))?
            .json()
            .await
            .map_err(|e| format!("activate response invalid: {}", e))?;
        let recovered = hex::decode(field(&resp, "secret").map_err(|_| format!("credential activation failed: {}", resp))?)
            .map_err(|_| "activated secret not hex".to_string())?;
        if recovered.len() != credential.len() || !openssl::memcmp::eq(&recovered, &credential) {
            return Err("credential activation returned the wrong secret: AK and EK are not in the same TPM".into());
        }
        checks.push("TPM2_ActivateCredential proved the AK resides in the certified TPM".into());

        let cert_der = openssl::x509::X509::from_pem(ek_cert.as_bytes())
            .and_then(|c| c.to_der())
            .map_err(|e| e.to_string())?;
        Ok((
            TpmEnrollment {
                ak_public: field(&info, "ak_public")?.to_string(),
                ak_name: hex::encode(&ak.name),
                ek_cert_sha256: hex::encode(hash(MessageDigest::sha256(), &cert_der).unwrap()),
                enrolled_at: Utc::now().timestamp(),
            },
            checks,
        ))
    }

    async fn enroll_optee(&self) -> Result<(OpteeEnrollment, Vec<String>), String> {
        let url = format!("{}?op=pubkey", self.cfg.optee_url);
        let info = get_json(&self.client, &url).await?;
        if field(&info, "alg")? != optee::PTA_SIG_ALG {
            return Err(format!("unexpected PTA signature algorithm {}", field(&info, "alg")?));
        }
        let (e, n) = (field(&info, "e")?, field(&info, "n")?);
        optee::public_key(e, n)?;
        Ok((
            OpteeEnrollment {
                e: e.to_string(),
                n: n.to_string(),
                fingerprint: optee::key_fingerprint(n),
                enrolled_at: Utc::now().timestamp(),
            },
            vec!["OP-TEE PTA attestation key (RSASSA-PSS) registered at provisioning".into()],
        ))
    }

    // ------------------------------------------------------------ collection

    /// Collect fresh evidence from every enrolled RoT, bound to `challenge`.
    /// Evidence that fails verification is not admitted (Auth = 0).
    pub async fn collect(&self, session_id: &str, challenge: &str) -> (Vec<CollectedNode>, Vec<RotReport>) {
        let enrollment = self.enrollment();
        let mut nodes = Vec::new();
        let mut reports = Vec::new();

        let tpm_result = match &enrollment.tpm {
            Some(e) => self.collect_tpm(e, session_id, challenge).await,
            None => Err("TPM not enrolled (POST /mral/enroll)".into()),
        };
        let optee_result = match &enrollment.optee {
            Some(e) => self.collect_optee(e, session_id, challenge).await,
            None => Err("OP-TEE not enrolled (POST /mral/enroll)".into()),
        };
        for (rot, result) in [("tpm", tpm_result), ("optee", optee_result)] {
            match result {
                Ok((mut n, checks)) => {
                    nodes.append(&mut n);
                    reports.push(RotReport { rot: rot.into(), verified: true, checks, error: None });
                }
                Err(err) => reports.push(RotReport { rot: rot.into(), verified: false, checks: vec![], error: Some(err) }),
            }
        }
        (nodes, reports)
    }

    async fn collect_tpm(
        &self,
        enrollment: &TpmEnrollment,
        session_id: &str,
        challenge: &str,
    ) -> Result<(Vec<CollectedNode>, Vec<String>), String> {
        let ak = tpm::parse_ak_public(&hex::decode(&enrollment.ak_public).map_err(|e| e.to_string())?)?;
        let nonce = qualifying_data("tpm", session_id, challenge);
        let pcr_list = QUOTED_PCRS.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
        let url = format!(
            "{}/quote?nonce={}&pcrs={}",
            self.cfg.tpm_url.trim_end_matches('/'),
            hex::encode(&nonce),
            pcr_list
        );
        let r = get_json(&self.client, &url).await?;

        let mut pcr_values = BTreeMap::new();
        if let Some(obj) = r.get("pcrs").and_then(|v| v.as_object()) {
            for (k, v) in obj {
                let idx: u32 = k.parse().map_err(|_| "bad PCR index".to_string())?;
                let val = hex::decode(v.as_str().unwrap_or("")).map_err(|_| "PCR not hex".to_string())?;
                pcr_values.insert(idx, val);
            }
        }
        let events: Vec<tpm::Event> = serde_json::from_value(r.get("event_log").cloned().unwrap_or(json!([])))
            .map_err(|e| format!("event log malformed: {}", e))?;
        let attest = unhex(&r, "attest")?;
        let q = tpm::verify_quote(
            &ak.key,
            &attest,
            &unhex(&r, "signature")?,
            &nonce,
            &QUOTED_PCRS,
            &pcr_values,
            &events,
        )?;
        let checks = vec![
            "TPM2_Quote signature verified with the enrolled AK (ECDSA-P256)".into(),
            "qualifying data equals H(sid, challenge): quote is fresh".into(),
            "reported PCRs hash to the TPM-signed PCR digest".into(),
            format!("measured-boot event log ({} events) replays to the quoted PCRs", events.len()),
        ];

        let layer_node = |layer: Layer, range: std::ops::RangeInclusive<u32>, parent| {
            let pcrs: BTreeMap<String, String> = range
                .clone()
                .map(|i| (i.to_string(), hex::encode(&pcr_values[&i])))
                .collect();
            let layer_events: Vec<&tpm::Event> = events.iter().filter(|e| range.contains(&e.pcr)).collect();
            CollectedNode {
                layer: layer.clone(),
                mode: Mode::BootTime,
                source: Source::Tpm,
                parent,
                evidence: json!({
                    "source": "tpm",
                    "rot": "TPM 2.0 (swtpm)",
                    "layer": format!("{:?}", layer),
                    "qualified_signer": hex::encode(&q.qualified_signer),
                    "extra_data": hex::encode(&q.extra_data),
                    "pcr_bank": "sha256",
                    "pcr_selection": range.clone().map(|i| i.to_string()).collect::<Vec<_>>().join(","),
                    "pcrs": pcrs,
                    "pcr_digest": hex::encode(&q.pcr_digest),
                    "clock_info": {
                        "clock": q.clock, "reset_count": q.reset_count,
                        "restart_count": q.restart_count, "safe": q.safe,
                    },
                    "firmware_version": format!("{:016x}", q.firmware_version),
                    "event_log": layer_events,
                    "quote": hex::encode(&attest),
                    "hostname": r.get("hostname").cloned().unwrap_or(Value::Null),
                }),
            }
        };
        Ok((
            vec![
                layer_node(Layer::Platform, PLATFORM_PCRS, None),
                layer_node(
                    Layer::Hypervisor,
                    HYPERVISOR_PCRS,
                    Some((Layer::Platform, ArgRelationship::VmIncludesHypervisor)),
                ),
            ],
            checks,
        ))
    }

    async fn collect_optee(
        &self,
        enrollment: &OpteeEnrollment,
        session_id: &str,
        challenge: &str,
    ) -> Result<(Vec<CollectedNode>, Vec<String>), String> {
        let key = optee::public_key(&enrollment.e, &enrollment.n)?;
        let nonce = qualifying_data("optee", session_id, challenge);
        let url = format!("{}?op=attest&nonce={}", self.cfg.optee_url, hex::encode(&nonce));
        let r = get_json(&self.client, &url).await?;

        if unhex(&r, "nonce")? != nonce {
            return Err("OP-TEE evidence is bound to a different nonce (stale or replayed)".into());
        }
        if field(&r, "ta_uuid")? != WORKLOAD_TA_UUID {
            return Err("OP-TEE evidence is for an unexpected TA".into());
        }
        let part = |name: &str| -> Result<(String, String), String> {
            let p = r.get(name).ok_or_else(|| format!("missing '{}'", name))?;
            Ok((field(p, "hash")?.to_string(), field(p, "sig")?.to_string()))
        };
        let (tee_hash, tee_sig) = part("tee_core")?;
        let (ta_hash, ta_sig) = part("ta_memory")?;
        let (shdr_hash, shdr_sig) = part("ta_shdr")?;
        optee::verify_measurement(&key, &nonce, &tee_hash, &tee_sig)?;
        optee::verify_measurement(&key, &nonce, &ta_hash, &ta_sig)?;
        optee::verify_measurement(&key, &nonce, &shdr_hash, &shdr_sig)?;
        let checks = vec![
            "TEE-core, TA-memory and TA-header signatures verified with the enrolled PTA key (RSASSA-PSS)".into(),
            "nonce equals H(sid, challenge): evidence is fresh".into(),
        ];

        let base = |layer: &Layer| {
            json!({
                "source": "optee",
                "rot": "OP-TEE 4.1 attestation PTA (Arm TrustZone)",
                "layer": format!("{:?}", layer),
                "nonce": hex::encode(&nonce),
                "sig_alg": "RSASSA-PSS-SHA256",
                "attestation_key_fpr": enrollment.fingerprint,
            })
        };
        let mut guest = base(&Layer::Guest);
        guest["tee_core_hash"] = json!(tee_hash);
        guest["signature"] = json!(tee_sig);
        let mut app = base(&Layer::Application);
        app["ta_uuid"] = json!(WORKLOAD_TA_UUID);
        app["ta_memory_hash"] = json!(ta_hash);
        app["ta_shdr_digest"] = json!(shdr_hash);
        app["signature"] = json!(ta_sig);
        app["shdr_signature"] = json!(shdr_sig);

        Ok((
            vec![
                CollectedNode {
                    layer: Layer::Guest,
                    mode: Mode::Runtime,
                    source: Source::OpTee,
                    evidence: guest,
                    parent: Some((Layer::Platform, ArgRelationship::TeeAnchoredInPlatform)),
                },
                CollectedNode {
                    layer: Layer::Application,
                    mode: Mode::Runtime,
                    source: Source::OpTee,
                    evidence: app,
                    parent: Some((Layer::Guest, ArgRelationship::RuntimeLinkedToBoot)),
                },
            ],
            checks,
        ))
    }
}
