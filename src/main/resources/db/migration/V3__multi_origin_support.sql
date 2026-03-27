-- ============================================================
-- V3 — Multi-origin support per RP
-- Widens the rp_config.origin column to hold a comma-separated
-- list of allowed origins (e.g. "https://app.example.com,https://app2.example.com")
-- ============================================================

ALTER TABLE rp_config
    MODIFY COLUMN origin VARCHAR(2048) NOT NULL
        COMMENT 'Comma-separated list of allowed origins (scheme+host+port, no trailing slash)';
