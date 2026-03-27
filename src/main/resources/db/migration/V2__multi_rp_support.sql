-- ============================================================
-- V2 — Multi-RP support
-- Adds rp_config table and scopes credentials/sessions to an RP
-- ============================================================

-- ── rp_config ─────────────────────────────────────────────────────────────────
-- Each row is one Relying Party identity.
-- rp_password is used for Basic Auth: Authorization: Basic base64(rp_id:rp_password)
-- IMPORTANT: store a strong random password per RP in production.
CREATE TABLE IF NOT EXISTS rp_config (
    id                    BIGINT          NOT NULL AUTO_INCREMENT,
    rp_id                 VARCHAR(256)    NOT NULL COMMENT 'WebAuthn Relying Party ID (effective domain)',
    rp_name               VARCHAR(256)    NOT NULL COMMENT 'Human-readable RP name shown in authenticator prompts',
    origin                VARCHAR(512)    NOT NULL COMMENT 'Full origin seen by browser: scheme+host+port, no trailing slash',
    challenge_ttl_seconds BIGINT          NOT NULL DEFAULT 180 COMMENT 'Challenge time-to-live in seconds',
    rp_password           VARCHAR(256)    NOT NULL COMMENT 'Password for Basic Auth: Basic base64(rp_id:rp_password)',
    active                TINYINT(1)      NOT NULL DEFAULT 1 COMMENT '0 = disabled, all requests rejected',
    created_at            DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at            DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),

    PRIMARY KEY (id),
    UNIQUE KEY uk_rp_config_rp_id (rp_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='FIDO2 Relying Party configuration — one row per RP';

-- Seed the default localhost RP so existing data and local development work immediately
INSERT INTO rp_config (rp_id, rp_name, origin, challenge_ttl_seconds, rp_password, active)
VALUES ('localhost', 'FIDO2 Demo Application', 'http://localhost:8080', 180, 'fido123', 1);

-- ── credentials: add rp_id column ─────────────────────────────────────────────
-- Existing credentials are assigned to 'localhost' (the only RP prior to this migration)
ALTER TABLE credentials
    ADD COLUMN rp_id VARCHAR(256) NOT NULL DEFAULT 'localhost'
        COMMENT 'RP this credential was registered with'
        AFTER username,
    ADD INDEX idx_credentials_rp_id (rp_id),
    ADD CONSTRAINT fk_credentials_rp
        FOREIGN KEY (rp_id) REFERENCES rp_config(rp_id) ON UPDATE CASCADE;

-- ── challenge_sessions: add rp_id column ──────────────────────────────────────
ALTER TABLE challenge_sessions
    ADD COLUMN rp_id VARCHAR(256) NOT NULL DEFAULT 'localhost'
        COMMENT 'RP this challenge session belongs to'
        AFTER username;
