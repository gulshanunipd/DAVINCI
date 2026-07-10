# 🔒 Privacy Control Engine (PCE)

## 📖 Overview

Il **Privacy Control Engine (PCE)** è il componente *privacy‑preserving* del sistema **DAVINCI**.
Agisce come *gatekeeper*: ogni *evidence* diretta verso **AMC/ARG** deve transitare dal PCE, che applica trasformazioni privacy‑aware mantenendo le proprietà di verificabilità crittografica.

**Obiettivi principali**:

* **Privacy by Design** – Nessun dato sensibile viene persistito in chiaro
* **Verifiability Preservation** – Le trasformazioni non rompono la verificabilità
* **Policy Enforcement** – Solo evidence conformi alle policy vengono accettate

---

## 🧱 Ruolo Architetturale

```
Evidence Source (TPM / TDX / SEV-SNP / CCA)
            │
            ▼
      Privacy Control Engine (PCE)
            │
            ▼
     AMC / ARG / Verifier
```

Il PCE è **stateless verso l'esterno**, ma internamente gestisce:

* pseudonimi session‑scoped
* valutazione del rischio privacy
* applicazione di disclosure policy
* validazione policy multi‑pass

---

## ⚙️ Principi di Funzionamento

### 1️⃣ Session‑Scoped Pseudonymization

```
Pseudonym = SHA256(
  SHA256(session_id) || field_name || original_value
)[0:16]
```

**Proprietà**:

* **Session‑bound**: stesso valore → pseudonimi diversi in sessioni diverse
* **Deterministico**: stesso valore nella stessa sessione → stesso pseudonimo
* **Unlinkable**: impossibile correlare identità cross‑session
* **One‑way**: non reversibile senza database di mapping

---

### 2️⃣ Selective Disclosure

Ogni *source* definisce tre categorie di campi:

| Categoria    | Trattamento         | Esempi                        |
| ------------ | ------------------- | ----------------------------- |
| Required     | mantenuti in chiaro | `pcr_digest`, `measurement`   |
| Aggregatable | hash SHA‑256        | `ima_log`, `event_log`        |
| Redacted     | rimossi             | `firmware_version`, `chip_id` |

---

### 3️⃣ Risk Detection

Analisi *source‑aware* **pre‑trasformazione**:

| Tipo               | Campi                                          | Severity  |
| ------------------ | ---------------------------------------------- | --------- |
| Stable identifiers | `aik_cert`, `ek_cert`, `vcek_cert`, `mrseam`   | 🔴 HIGH   |
| Fingerprinting     | `firmware_version`, `tee_tcb_svn`, `host_data` | 🟠 MEDIUM |
| Large datasets     | `ima_log > 100 entries`                        | 🟠 MEDIUM |

---

### 4️⃣ Policy‑Based Validation

**Meccanismo a due passaggi**:

1. **Policy specifica** (layer + mode + source)
2. **Policy universali** (cross‑cutting, blacklist, freshness)

Violazioni con **severity CRITICAL** ⇒ **reject node**

---

## ✅ Stato Attuale – Implementato

### 1. Pseudonymization (`pseudonymization.rs`)

* `PseudonymManager` con session key derivation (SHA‑256)
* `pseudonymize()` deterministico + cache in‑memory
* `detect_risks()` source‑aware (TPM / TDX / SNP / CCA)
* Classificazione privacy risk

---

### 2. Selective Disclosure (`disclosure.rs`)

**DisclosurePolicy per source**:

* TPM: 5 required · 2 aggregatable · 2 redact
* TDX: 6 required · 1 aggregatable · 4 redact
* SNP: 6 required · 3 aggregatable · 5 redact
* CCA: 8 required · 1 aggregatable · 3 redact

Pipeline:

```
redact → aggregate → retain
```

---

### 3. Policy Validation (`policy.rs`, `validators.rs`)

* Versioned policy model
* Applicability matching (layer / mode / source)
* Two‑pass discovery
* Rule types:

  * field_presence
  * field_pattern (regex)
  * timestamp_age
* Severity‑based enforcement

---

### 4. HTTP Service (`main.rs`)

**Endpoints**:

* `POST /privacy/transform`
* `POST /validate/node`
* `GET /health`

**Stack**:

* Warp HTTP server
* JSON policies loaded at startup
* Graceful error handling

---

### 5. Integration

* Invocato dall'Attestation Manager
* **Graceful degradation** se PCE offline
* Status: `success` | `success_without_privacy`

---

## ❌ Gap Critici per Prototipo Completo

### 🔴 1. Database Persistence

**Problema**: mapping pseudonimi solo in‑memory

**Soluzione**: PostgreSQL

Schema:

```sql
CREATE TABLE pseudonym_mappings (
  id SERIAL PRIMARY KEY,
  session_id VARCHAR(255),
  field_name VARCHAR(255),
  original_value TEXT,
  pseudonym VARCHAR(64),
  public_key_der BYTEA,
  created_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(session_id, field_name, original_value)
);
```

---

### 🔴 2. Pseudonym Resolution Endpoint

Endpoint richiesto:

```
POST /resolve/pseudonym
```

Permette al **Verifier** di recuperare la public key associata a un pseudonimo.

---

### 🔴 3. Public Key Extraction da Certificati

Necessario quando si pseudonimizzano:

* `aik_cert`
* `vcek_cert`

Uso di `openssl::x509` per estrarre la public key **prima** della sostituzione.

---

## 🟡 Gap Non‑Critici (Nice‑to‑Have)

* Advanced risk scoring (0‑100)
* Policy hot‑reload
* Audit logging strutturato (`tracing`)
* Rate limiting (tower‑governor)
* Prometheus metrics

---

## 📊 Checklist Riepilogativa

| Componente           | Stato | Priorità |
| -------------------- | ----- | -------- |
| Pseudonymization     | ✅     | –        |
| Selective disclosure | ✅     | –        |
| Policy validation    | ✅     | –        |
| DB persistence       | ❌     | 🔴       |
| /resolve endpoint    | ❌     | 🔴       |
| Pubkey extraction    | ❌     | 🔴       |

---

## 🎯 Priorità di Completamento

### Weekend 3‑4 (Must‑Have)

* PostgreSQL schema + migrations
* DB‑backed `PseudonymManager`
* `/resolve/pseudonym`
* Public key extraction

### Weekend 5‑6 (Should‑Have)

* Audit logging
* Rate limiting

### Extra

* Metrics
* Policy reload
* Advanced risk scoring

---

## 🧠 Sintesi

Il PCE implementa ~**70%** delle funzionalità core.
Le **3 feature critiche mancanti** (DB, resolve, pubkey extraction) bloccano la verifica end‑to‑end.

👉 **Con ~4 giorni di lavoro** il prototipo può diventare completo e demo‑ready.
