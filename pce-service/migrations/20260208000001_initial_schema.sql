-- Initial schema for PCE persistence layer

-- Public keys extracted from certificates
CREATE TABLE IF NOT EXISTS public_keys (
    id SERIAL PRIMARY KEY,
    key_type VARCHAR(50) NOT NULL,           -- "RSA-2048", "ECDSA-P256", etc.
    key_der BYTEA NOT NULL,                  -- DER-encoded public key
    key_fingerprint VARCHAR(64) NOT NULL UNIQUE, -- SHA256(key_der) as hex
    source VARCHAR(50) NOT NULL,             -- "TPM_AIK", "SNP_VCEK", "TDX_QUOTE", "CCA_REALM"
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Index for fast fingerprint lookups
CREATE INDEX idx_public_keys_fingerprint ON public_keys(key_fingerprint);
CREATE INDEX idx_public_keys_source ON public_keys(source);

-- Pseudonym mappings (session-scoped)
CREATE TABLE IF NOT EXISTS pseudonym_mappings (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(255) NOT NULL,        -- Session identifier from Attestation Manager
    field_name VARCHAR(255) NOT NULL,        -- "aik_cert", "vcek_cert", "mrseam", etc.
    original_hash VARCHAR(64) NOT NULL,      -- SHA256(original_value) for privacy
    pseudonym VARCHAR(64) NOT NULL,          -- "psn_<hex16>"
    public_key_id INTEGER REFERENCES public_keys(id) ON DELETE SET NULL, -- FK to public_keys
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    -- Ensure no duplicate mappings within same session
    UNIQUE(session_id, field_name, original_hash)
);

-- Index for fast session lookups
CREATE INDEX idx_pseudonym_mappings_session ON pseudonym_mappings(session_id);
-- Index for fast pseudonym resolution
CREATE INDEX idx_pseudonym_mappings_pseudonym ON pseudonym_mappings(session_id, pseudonym);
-- Index for field queries
CREATE INDEX idx_pseudonym_mappings_field ON pseudonym_mappings(field_name);

-- Audit log (optional, for compliance tracking)
CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
    action VARCHAR(50) NOT NULL,             -- "transform", "resolve", "validate"
    session_id VARCHAR(255),
    source_type VARCHAR(50),                 -- "Tpm", "Tdx", "SevSnp", "Cca"
    client_ip INET,
    success BOOLEAN NOT NULL,
    error_message TEXT,
    
    -- Additional metadata as JSON
    metadata JSONB
);

-- Index for time-based queries
CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp DESC);
-- Index for session tracking
CREATE INDEX idx_audit_log_session ON audit_log(session_id);
-- Index for failure analysis
CREATE INDEX idx_audit_log_failures ON audit_log(success) WHERE success = false;
