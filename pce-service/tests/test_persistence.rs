use pce_service::{PostgresPseudonymStore, PseudonymStore, PseudonymMapping};
use chrono::Utc;

#[tokio::test]
async fn test_store_and_resolve_pseudonym() {
    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://pce:pce_password@localhost:5432/pce".to_string());
    
    let store = PostgresPseudonymStore::from_url(&db_url)
        .await
        .expect("Failed to connect to DB");
    
    // Create test mapping
    let mapping = PseudonymMapping {
        id: None,
        session_id: "test_session_123".to_string(),
        field_name: "aik_cert".to_string(),
        original_hash: "abc123hash".to_string(),
        pseudonym: "psn_test001".to_string(),
        public_key_id: None,
        created_at: Utc::now(),
    };
    
    // Store it
    let id = store.store_mapping(mapping.clone()).await.expect("Failed to store mapping");
    assert!(id > 0, "ID should be positive");
    
    // Resolve it
    let resolved = store.resolve("test_session_123", "psn_test001")
        .await
        .expect("Failed to resolve pseudonym");
    
    assert_eq!(resolved.pseudonym, "psn_test001");
    assert_eq!(resolved.field_name, "aik_cert");
    assert_eq!(resolved.public_key_pem, None); // No key attached
    
    println!("✅ Store and resolve test passed!");
}

#[tokio::test]
async fn test_health_check() {
    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://pce:pce_password@localhost:5432/pce".to_string());
    
    let store = PostgresPseudonymStore::from_url(&db_url).await.unwrap();
    
    assert!(store.health_check().await, "DB should be healthy");
    println!("✅ Health check test passed!");
}