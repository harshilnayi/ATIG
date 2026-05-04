-- ATIG Database Schema
-- Run this automatically via Docker init

-- Alerts table
CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    severity VARCHAR(20) NOT NULL,
    detection_type VARCHAR(50) NOT NULL,
    source_ip INET,
    dest_ip INET,
    source_port INTEGER,
    dest_port INTEGER,
    protocol VARCHAR(10),
    signature_id VARCHAR(50),
    signature_msg TEXT,
    anomaly_score FLOAT,
    raw_payload JSONB,
    acknowledged BOOLEAN DEFAULT FALSE,
    resolved BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Network flows
CREATE TABLE IF NOT EXISTS network_flows (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    start_time TIMESTAMPTZ NOT NULL,
    end_time TIMESTAMPTZ,
    src_ip INET NOT NULL,
    dst_ip INET NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    protocol VARCHAR(10),
    bytes_sent BIGINT,
    bytes_received BIGINT,
    packets_sent INTEGER,
    packets_received INTEGER,
    flags TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Threat indicators
CREATE TABLE IF NOT EXISTS threat_indicators (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    indicator_type VARCHAR(20) NOT NULL,
    indicator_value TEXT NOT NULL UNIQUE,
    source VARCHAR(50) NOT NULL,
    confidence INTEGER,
    tags TEXT[],
    first_seen TIMESTAMPTZ,
    last_updated TIMESTAMPTZ,
    expired BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Detection rules
CREATE TABLE IF NOT EXISTS detection_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id VARCHAR(50) UNIQUE NOT NULL,
    message TEXT,
    protocol VARCHAR(10),
    src_ip CIDR,
    dst_ip CIDR,
    src_port TEXT,
    dst_port TEXT,
    content_match TEXT,
    regex_pattern TEXT,
    severity VARCHAR(20),
    enabled BOOLEAN DEFAULT TRUE,
    category VARCHAR(50),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_flows_src_ip ON network_flows(src_ip);
CREATE INDEX IF NOT EXISTS idx_flows_dst_ip ON network_flows(dst_ip);
CREATE INDEX IF NOT EXISTS idx_indicators_value ON threat_indicators(indicator_value);
CREATE INDEX IF NOT EXISTS idx_indicators_type ON threat_indicators(indicator_type);
