-- ASTRA Initial PostgreSQL + pgvector Schema (001_initial_astra_schema.sql)
-- Enforces Tenant & Legal-Entity Isolation (SEC-07), Exact Minor-Unit Money (SEC-24),
-- Idempotency Keys (SEC-23), Durable Outbox Leases, and Hash-Chained Audit Trail (SEC-27).

CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS legal_entities (
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id),
    legal_entity_id VARCHAR(64) NOT NULL,
    name VARCHAR(255) NOT NULL,
    functional_currency CHAR(3) NOT NULL,
    timezone VARCHAR(64) NOT NULL DEFAULT 'UTC',
    current_open_period CHAR(7) NOT NULL,
    auto_post_limit_minor BIGINT NOT NULL DEFAULT 5000000,
    PRIMARY KEY (tenant_id, legal_entity_id)
);

CREATE TABLE IF NOT EXISTS payer_profiles (
    tenant_id VARCHAR(64) NOT NULL,
    legal_entity_id VARCHAR(64) NOT NULL,
    customer_id VARCHAR(64) NOT NULL,
    canonical_name VARCHAR(255) NOT NULL,
    approved_aliases JSONB NOT NULL DEFAULT '[]'::jsonb,
    invoice_regex VARCHAR(255) NOT NULL DEFAULT '^INV-\d{4,8}$',
    typical_delay_days INT NOT NULL DEFAULT 0,
    prefers_po_reference BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, legal_entity_id, customer_id)
);

CREATE TABLE IF NOT EXISTS raw_artifacts (
    artifact_id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    legal_entity_id VARCHAR(64) NOT NULL,
    source_channel VARCHAR(64) NOT NULL,
    content_sha256 CHAR(64) NOT NULL,
    storage_locator VARCHAR(512) NOT NULL,
    mime_type VARCHAR(128) NOT NULL,
    byte_size BIGINT NOT NULL CHECK (byte_size >= 0),
    legal_hold BOOLEAN NOT NULL DEFAULT FALSE,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, legal_entity_id, content_sha256)
);

CREATE TABLE IF NOT EXISTS receipts (
    receipt_id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    legal_entity_id VARCHAR(64) NOT NULL,
    idempotency_key VARCHAR(128) NOT NULL,
    source_channel VARCHAR(64) NOT NULL,
    artifact_id VARCHAR(64) NOT NULL REFERENCES raw_artifacts(artifact_id),
    bank_account_masked VARCHAR(64) NOT NULL,
    bank_reference VARCHAR(128) NOT NULL,
    payer_name_raw VARCHAR(255) NOT NULL,
    customer_id VARCHAR(64),
    currency CHAR(3) NOT NULL,
    exponent SMALLINT NOT NULL CHECK (exponent IN (0, 2, 3)),
    gross_amount_minor BIGINT NOT NULL CHECK (gross_amount_minor >= 0),
    fee_amount_minor BIGINT NOT NULL DEFAULT 0 CHECK (fee_amount_minor >= 0),
    net_amount_minor BIGINT NOT NULL CHECK (net_amount_minor >= 0),
    applied_amount_minor BIGINT NOT NULL DEFAULT 0 CHECK (applied_amount_minor >= 0),
    unapplied_amount_minor BIGINT NOT NULL DEFAULT 0 CHECK (unapplied_amount_minor >= 0),
    value_date DATE NOT NULL,
    posting_period CHAR(7) NOT NULL,
    state VARCHAR(32) NOT NULL CHECK (state IN (
        'received', 'normalized', 'matched', 'needs_review', 'unapplied',
        'quarantined', 'approved_as_required', 'posting_pending',
        'posted', 'posting_failed', 'reconciled', 'reversed'
    )),
    match_tier SMALLINT,
    confidence NUMERIC(5, 4),
    score_margin NUMERIC(5, 4),
    preparer_id VARCHAR(64),
    approver_id VARCHAR(64),
    reversal_of_receipt_id VARCHAR(64) REFERENCES receipts(receipt_id),
    version INT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, legal_entity_id, idempotency_key),
    CHECK (net_amount_minor = applied_amount_minor + unapplied_amount_minor),
    CHECK (gross_amount_minor = net_amount_minor + fee_amount_minor)
);

CREATE INDEX IF NOT EXISTS idx_receipts_entity_state_date
    ON receipts (tenant_id, legal_entity_id, state, value_date);

CREATE TABLE IF NOT EXISTS open_items (
    item_id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    legal_entity_id VARCHAR(64) NOT NULL,
    customer_id VARCHAR(64) NOT NULL,
    invoice_number VARCHAR(64) NOT NULL,
    po_number VARCHAR(64),
    currency CHAR(3) NOT NULL,
    original_amount_minor BIGINT NOT NULL CHECK (original_amount_minor >= 0),
    open_amount_minor BIGINT NOT NULL,
    discount_terms_bps INT NOT NULL DEFAULT 0,
    discount_due_date DATE,
    due_date DATE NOT NULL,
    snapshot_version INT NOT NULL DEFAULT 1,
    as_of TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, legal_entity_id, invoice_number)
);

CREATE TABLE IF NOT EXISTS allocations (
    allocation_id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    legal_entity_id VARCHAR(64) NOT NULL,
    receipt_id VARCHAR(64) NOT NULL REFERENCES receipts(receipt_id),
    item_id VARCHAR(64) NOT NULL REFERENCES open_items(item_id),
    invoice_number VARCHAR(64) NOT NULL,
    applied_minor BIGINT NOT NULL CHECK (applied_minor >= 0),
    discount_applied_minor BIGINT NOT NULL DEFAULT 0 CHECK (discount_applied_minor >= 0),
    residual_minor BIGINT NOT NULL CHECK (residual_minor >= 0),
    reason_code VARCHAR(64) NOT NULL,
    evidence_locator VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS deduction_cases (
    case_id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    legal_entity_id VARCHAR(64) NOT NULL,
    customer_id VARCHAR(64) NOT NULL,
    receipt_id VARCHAR(64) NOT NULL REFERENCES receipts(receipt_id),
    invoice_number VARCHAR(64) NOT NULL,
    currency CHAR(3) NOT NULL,
    received_minor BIGINT NOT NULL,
    open_minor BIGINT NOT NULL,
    residual_minor BIGINT NOT NULL CHECK (residual_minor > 0),
    taxonomy_version VARCHAR(32) NOT NULL,
    extracted_stated_reason TEXT,
    predicted_reason VARCHAR(64) NOT NULL,
    classifier_source VARCHAR(64) NOT NULL,
    confidence NUMERIC(5, 4) NOT NULL,
    evidence_locators JSONB NOT NULL,
    approved_route VARCHAR(64) NOT NULL,
    risk_snapshot_ref VARCHAR(64),
    external_status VARCHAR(32) NOT NULL DEFAULT 'draft',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS posting_intents (
    posting_intent_id VARCHAR(64) PRIMARY KEY,
    idempotency_key VARCHAR(128) NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    legal_entity_id VARCHAR(64) NOT NULL,
    receipt_id VARCHAR(64) NOT NULL REFERENCES receipts(receipt_id),
    erp_target VARCHAR(64) NOT NULL,
    posting_period CHAR(7) NOT NULL,
    payload_json JSONB NOT NULL,
    preparer_id VARCHAR(64) NOT NULL,
    approver_id VARCHAR(64),
    external_document_number VARCHAR(128),
    status VARCHAR(32) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, legal_entity_id, idempotency_key),
    CHECK (approver_id IS NULL OR approver_id <> preparer_id)
);

CREATE TABLE IF NOT EXISTS job_outbox (
    job_id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    legal_entity_id VARCHAR(64) NOT NULL,
    topic VARCHAR(64) NOT NULL,
    idempotency_key VARCHAR(128) NOT NULL,
    payload_json JSONB NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'queued',
    attempts INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 5,
    lease_owner VARCHAR(64),
    lease_expires_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, legal_entity_id, topic, idempotency_key)
);

CREATE TABLE IF NOT EXISTS rag_chunks (
    chunk_id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    legal_entity_id VARCHAR(64) NOT NULL,
    doc_id VARCHAR(64) NOT NULL,
    source_locator VARCHAR(255) NOT NULL,
    chunk_text TEXT NOT NULL,
    embedding vector(64) NOT NULL,
    legal_hold BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rag_chunks_scope
    ON rag_chunks (tenant_id, legal_entity_id, doc_id);

CREATE TABLE IF NOT EXISTS audit_events (
    seq BIGSERIAL PRIMARY KEY,
    event_id VARCHAR(64) NOT NULL UNIQUE,
    tenant_id VARCHAR(64) NOT NULL,
    legal_entity_id VARCHAR(64) NOT NULL,
    actor_id VARCHAR(64) NOT NULL,
    actor_role VARCHAR(64) NOT NULL,
    action VARCHAR(128) NOT NULL,
    target_type VARCHAR(64) NOT NULL,
    target_id VARCHAR(128) NOT NULL,
    policy_version VARCHAR(32) NOT NULL,
    details_json JSONB NOT NULL,
    prev_hash CHAR(64) NOT NULL,
    event_hash CHAR(64) NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
