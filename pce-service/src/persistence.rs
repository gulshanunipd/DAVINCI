//! Database persistence layer for pseudonym mappings and public keys

use sqlx::{PgPool, Row};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::sync::Arc;

/// Result type for persistence operations
pub type PersistenceResult<T> = Result<T, PersistenceError>;

/// Errors that can occur during persistence operations
#[derive(Debug, thiserror::Error)]
pub enum PersistenceError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    
    #[error("Migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
    
    #[error("Pseudonym not found: {0}")]
    PseudonymNotFound(String),
    
    #[error("Public key not found: {0}")]
    PublicKeyNotFound(String),
    
    #[error("Invalid data: {0}")]
    InvalidData(String),
}

/// Public key metadata stored in database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    pub id: Option<i32>,
    pub key_type: String,           // "RSA-2048", "ECDSA-P256"
    pub key_der: Vec<u8>,           // DER-encoded public key
    pub key_fingerprint: String,    // SHA256(key_der) as hex
    pub source: String,             // "TPM_AIK", "SNP_VCEK", "TDX_QUOTE"
    pub created_at: DateTime<Utc>,
}

/// Pseudonym mapping stored in database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PseudonymMapping {
    pub id: Option<i32>,
    pub session_id: String,
    pub field_name: String,
    pub original_hash: String,      // SHA256(original_value) - privacy protection
    pub pseudonym: String,          // "psn_<hex16>"
    pub public_key_id: Option<i32>, // FK to public_keys (if certificate)
    pub created_at: DateTime<Utc>,
}

/// Resolved pseudonym with public key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedKey {
    pub pseudonym: String,
    pub field_name: String,
    pub public_key_pem: Option<String>,
    pub key_type: Option<String>,
    pub source: Option<String>,
}

/// Trait for pseudonym storage operations
#[async_trait::async_trait]
pub trait PseudonymStore: Send + Sync {
    /// Store a new pseudonym mapping
    async fn store_mapping(&self, mapping: PseudonymMapping) -> PersistenceResult<i32>;
    
    /// Resolve a pseudonym to its public key
    async fn resolve(&self, session_id: &str, pseudonym: &str) -> PersistenceResult<ResolvedKey>;
    
    /// Store a public key (returns existing ID if duplicate)
    async fn store_public_key(&self, key: PublicKey) -> PersistenceResult<i32>;
    
    /// List all pseudonyms for a session
    async fn list_by_session(&self, session_id: &str) -> PersistenceResult<Vec<PseudonymMapping>>;
    
    /// Check if store is healthy (DB connection alive)
    async fn health_check(&self) -> bool;
}

/// PostgreSQL implementation of PseudonymStore
pub struct PostgresPseudonymStore {
    pool: PgPool,
}

impl PostgresPseudonymStore {
    /// Create a new PostgreSQL store
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
    
    /// Create a new store from connection string
    pub async fn from_url(database_url: &str) -> PersistenceResult<Self> {
        let pool = PgPool::connect(database_url).await?;
        Ok(Self::new(pool))
    }
    
    /// Run database migrations
    pub async fn migrate(&self) -> PersistenceResult<()> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl PseudonymStore for PostgresPseudonymStore {
    async fn store_mapping(&self, mapping: PseudonymMapping) -> PersistenceResult<i32> {
        let id = sqlx::query(
            r#"
            INSERT INTO pseudonym_mappings 
                (session_id, field_name, original_hash, pseudonym, public_key_id, created_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (session_id, field_name, original_hash) 
            DO UPDATE SET pseudonym = EXCLUDED.pseudonym
            RETURNING id
            "#
        )
        .bind(&mapping.session_id)
        .bind(&mapping.field_name)
        .bind(&mapping.original_hash)
        .bind(&mapping.pseudonym)
        .bind(mapping.public_key_id)
        .bind(mapping.created_at)
        .fetch_one(&self.pool)
        .await?
        .get::<i32, _>(0);
        
        Ok(id)
    }
    
    async fn resolve(&self, session_id: &str, pseudonym: &str) -> PersistenceResult<ResolvedKey> {
        let row = sqlx::query(
            r#"
            SELECT 
                pm.pseudonym,
                pm.field_name,
                pk.key_der,
                pk.key_type,
                pk.source
            FROM pseudonym_mappings pm
            LEFT JOIN public_keys pk ON pm.public_key_id = pk.id
            WHERE pm.session_id = $1 AND pm.pseudonym = $2
            "#
        )
        .bind(session_id)
        .bind(pseudonym)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| PersistenceError::PseudonymNotFound(pseudonym.to_string()))?;
        
        let key_der: Option<Vec<u8>> = row.get("key_der");
        let public_key_pem = key_der.map(|der| {
            // Convert DER to PEM
            let pem = openssl::pkey::PKey::public_key_from_der(&der)
                .and_then(|k| k.public_key_to_pem())
                .unwrap_or_default();
            String::from_utf8_lossy(&pem).to_string()
        });
        
        Ok(ResolvedKey {
            pseudonym: row.get("pseudonym"),
            field_name: row.get("field_name"),
            public_key_pem,
            key_type: row.get("key_type"),
            source: row.get("source"),
        })
    }
    
    async fn store_public_key(&self, key: PublicKey) -> PersistenceResult<i32> {
        let id = sqlx::query(
            r#"
            INSERT INTO public_keys 
                (key_type, key_der, key_fingerprint, source, created_at)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (key_fingerprint) 
            DO UPDATE SET key_type = EXCLUDED.key_type
            RETURNING id
            "#
        )
        .bind(&key.key_type)
        .bind(&key.key_der)
        .bind(&key.key_fingerprint)
        .bind(&key.source)
        .bind(key.created_at)
        .fetch_one(&self.pool)
        .await?
        .get::<i32, _>(0);
        
        Ok(id)
    }
    
    async fn list_by_session(&self, session_id: &str) -> PersistenceResult<Vec<PseudonymMapping>> {
        let rows = sqlx::query_as::<_, (i32, String, String, String, String, Option<i32>, DateTime<Utc>)>(
            r#"
            SELECT id, session_id, field_name, original_hash, pseudonym, public_key_id, created_at
            FROM pseudonym_mappings
            WHERE session_id = $1
            ORDER BY created_at DESC
            "#
        )
        .bind(session_id)
        .fetch_all(&self.pool)
        .await?;
        
        let mappings = rows.into_iter().map(|(id, session_id, field_name, original_hash, pseudonym, public_key_id, created_at)| {
            PseudonymMapping {
                id: Some(id),
                session_id,
                field_name,
                original_hash,
                pseudonym,
                public_key_id,
                created_at,
            }
        }).collect();
        
        Ok(mappings)
    }
    
    async fn health_check(&self) -> bool {
        sqlx::query("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .is_ok()
    }
}

/// In-memory implementation for testing/fallback
pub struct InMemoryPseudonymStore {
    mappings: Arc<tokio::sync::RwLock<Vec<PseudonymMapping>>>,
    keys: Arc<tokio::sync::RwLock<Vec<PublicKey>>>,
}

impl InMemoryPseudonymStore {
    pub fn new() -> Self {
        Self {
            mappings: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            keys: Arc::new(tokio::sync::RwLock::new(Vec::new())),
        }
    }
}

impl Default for InMemoryPseudonymStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl PseudonymStore for InMemoryPseudonymStore {
    async fn store_mapping(&self, mut mapping: PseudonymMapping) -> PersistenceResult<i32> {
        let mut mappings = self.mappings.write().await;
        
        // Check for existing mapping
        if let Some(existing) = mappings.iter().find(|m| 
            m.session_id == mapping.session_id && 
            m.field_name == mapping.field_name &&
            m.original_hash == mapping.original_hash
        ) {
            return Ok(existing.id.unwrap_or(0));
        }
        
        let id = mappings.len() as i32 + 1;
        mapping.id = Some(id);
        mappings.push(mapping);
        Ok(id)
    }
    
    async fn resolve(&self, session_id: &str, pseudonym: &str) -> PersistenceResult<ResolvedKey> {
        let mappings = self.mappings.read().await;
        let mapping = mappings.iter()
            .find(|m| m.session_id == session_id && m.pseudonym == pseudonym)
            .ok_or_else(|| PersistenceError::PseudonymNotFound(pseudonym.to_string()))?;
        
        let mut resolved = ResolvedKey {
            pseudonym: mapping.pseudonym.clone(),
            field_name: mapping.field_name.clone(),
            public_key_pem: None,
            key_type: None,
            source: None,
        };
        
        if let Some(key_id) = mapping.public_key_id {
            let keys = self.keys.read().await;
            if let Some(key) = keys.iter().find(|k| k.id == Some(key_id)) {
                let pem = openssl::pkey::PKey::public_key_from_der(&key.key_der)
                    .and_then(|k| k.public_key_to_pem())
                    .ok()
                    .map(|pem| String::from_utf8_lossy(&pem).to_string());
                
                resolved.public_key_pem = pem;
                resolved.key_type = Some(key.key_type.clone());
                resolved.source = Some(key.source.clone());
            }
        }
        
        Ok(resolved)
    }
    
    async fn store_public_key(&self, mut key: PublicKey) -> PersistenceResult<i32> {
        let mut keys = self.keys.write().await;
        
        // Check for existing key by fingerprint
        if let Some(existing) = keys.iter().find(|k| k.key_fingerprint == key.key_fingerprint) {
            return Ok(existing.id.unwrap_or(0));
        }
        
        let id = keys.len() as i32 + 1;
        key.id = Some(id);
        keys.push(key);
        Ok(id)
    }
    
    async fn list_by_session(&self, session_id: &str) -> PersistenceResult<Vec<PseudonymMapping>> {
        let mappings = self.mappings.read().await;
        Ok(mappings.iter()
            .filter(|m| m.session_id == session_id)
            .cloned()
            .collect())
    }
    
    async fn health_check(&self) -> bool {
        true
    }
}
