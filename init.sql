-- ============================================
-- GHOST PROXY - DATABASE INITIALIZATION
-- ============================================

-- Enable UUID extension if needed
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================
-- AUDIT LOGS TABLE
-- ============================================

CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    log_id VARCHAR(32) UNIQUE NOT NULL,
    request_id VARCHAR(64) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    input_hash VARCHAR(64) NOT NULL,
    output_hash VARCHAR(64) NOT NULL,
    pii_count INTEGER DEFAULT 0,
    pii_redacted INTEGER DEFAULT 0,
    process_time_ms FLOAT NOT NULL,
    encrypted_payload TEXT,
    integrity_hash VARCHAR(64) NOT NULL,
    previous_hash VARCHAR(64) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_audit_log_id ON audit_logs(log_id);
CREATE INDEX IF NOT EXISTS idx_audit_request_id ON audit_logs(request_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_provider ON audit_logs(provider);

-- ============================================
-- REQUEST METRICS TABLE
-- ============================================

CREATE TABLE IF NOT EXISTS request_metrics (
    id SERIAL PRIMARY KEY,
    time_bucket TIMESTAMP WITH TIME ZONE NOT NULL,
    provider VARCHAR(50) NOT NULL,
    total_requests INTEGER DEFAULT 0,
    successful_requests INTEGER DEFAULT 0,
    failed_requests INTEGER DEFAULT 0,
    requests_with_pii INTEGER DEFAULT 0,
    total_pii_detected INTEGER DEFAULT 0,
    total_pii_redacted INTEGER DEFAULT 0,
    avg_process_time_ms FLOAT DEFAULT 0.0,
    min_process_time_ms FLOAT DEFAULT 0.0,
    max_process_time_ms FLOAT DEFAULT 0.0,
    p95_process_time_ms FLOAT DEFAULT 0.0,
    strict_mode_requests INTEGER DEFAULT 0,
    balanced_mode_requests INTEGER DEFAULT 0,
    permissive_mode_requests INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_metric_bucket ON request_metrics(time_bucket);
CREATE INDEX IF NOT EXISTS idx_metric_provider ON request_metrics(provider);
CREATE INDEX IF NOT EXISTS idx_metric_bucket_provider ON request_metrics(time_bucket, provider);

-- ============================================
-- SECURITY EVENTS TABLE
-- ============================================

CREATE TABLE IF NOT EXISTS security_events (
    id SERIAL PRIMARY KEY,
    event_id VARCHAR(32) UNIQUE NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    severity INTEGER NOT NULL,
    request_id VARCHAR(64),
    source_ip VARCHAR(45),
    user_agent VARCHAR(500),
    description TEXT NOT NULL,
    metadata JSONB,
    action_taken VARCHAR(100) NOT NULL,
    blocked BOOLEAN DEFAULT FALSE,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_security_event_id ON security_events(event_id);
CREATE INDEX IF NOT EXISTS idx_security_event_type ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_security_severity ON security_events(severity);
CREATE INDEX IF NOT EXISTS idx_security_timestamp ON security_events(timestamp);

-- ============================================
-- COMMENTS
-- ============================================

COMMENT ON TABLE audit_logs IS 'Encrypted audit trail for compliance and forensics';
COMMENT ON TABLE request_metrics IS 'Aggregated metrics for monitoring and alerting';
COMMENT ON TABLE security_events IS 'Security incidents and threat detection logs';

-- ============================================
-- GRANTS (if using specific roles)
-- ============================================

-- Grant all privileges to ghostproxy user (if exists)
-- DO $$
-- BEGIN
--    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'ghostproxy') THEN
--       CREATE ROLE ghostproxy WITH LOGIN PASSWORD 'securepassword';
--    END IF;
-- END
-- $$;

GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO ghostproxy;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO ghostproxy;