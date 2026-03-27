-- ============================================================
-- FIDO2 Backend — initial schema
-- Schema  : fidodb
-- User    : fidouser
-- ============================================================

-- ── users ─────────────────────────────────────────────────────────────────
-- Stores registered accounts.
-- user_id is the WebAuthn user handle (opaque, non-PII byte array stored
-- as base64url). username is the human-readable account identifier.
CREATE TABLE IF NOT EXISTS users (
    id          BIGINT          NOT NULL AUTO_INCREMENT,
    user_id     VARCHAR(24)     NOT NULL COMMENT 'Base64url-encoded 16-byte WebAuthn user handle',
    username    VARCHAR(256)    NOT NULL COMMENT 'Account identifier, e.g. email address',
    display_name VARCHAR(256)   NOT NULL COMMENT 'Human-readable name shown in authenticator prompts',
    created_at  DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    PRIMARY KEY (id),
    UNIQUE KEY uk_users_user_id   (user_id),
    UNIQUE KEY uk_users_username  (username)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='WebAuthn registered users';

-- ── credentials ───────────────────────────────────────────────────────────
-- One row per registered authenticator (passkey).
-- attested_credential_data stores the CBOR-serialised AttestedCredentialData
-- produced by AttestedCredentialDataConverter — it contains the public key.
-- sign_count must be updated after every successful authentication to detect
-- authenticator cloning (WebAuthn spec §6.1).
CREATE TABLE IF NOT EXISTS credentials (
    id                          BIGINT          NOT NULL AUTO_INCREMENT,
    credential_id               VARCHAR(512)    NOT NULL COMMENT 'Base64url-encoded authenticator credential ID',
    user_id                     VARCHAR(24)     NOT NULL COMMENT 'References users.user_id',
    username                    VARCHAR(256)    NOT NULL,
    attested_credential_data    LONGBLOB        NOT NULL COMMENT 'CBOR-serialised AttestedCredentialData (contains public key)',
    sign_count                  BIGINT          NOT NULL DEFAULT 0 COMMENT 'Authenticator signature counter — must increase each auth',
    transports                  VARCHAR(256)    NULL     COMMENT 'Comma-separated transport hints: internal,usb,nfc,ble,hybrid',
    registered_at               DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    last_used_at                DATETIME(3)     NULL,

    PRIMARY KEY (id),
    UNIQUE KEY uk_credentials_credential_id (credential_id),
    INDEX       idx_credentials_user_id     (user_id),
    CONSTRAINT  fk_credentials_user
        FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='WebAuthn registered credentials (passkeys)';

-- ── challenge_sessions ────────────────────────────────────────────────────
-- Short-lived records tracking pending registration/authentication ceremonies.
-- Each session is consumed (deleted) atomically when the ceremony completes
-- to prevent replay attacks. Expired rows are purged by a scheduled task.
CREATE TABLE IF NOT EXISTS challenge_sessions (
    session_id      VARCHAR(36)     NOT NULL COMMENT 'UUID v4 session identifier',
    challenge_bytes VARCHAR(64)     NOT NULL COMMENT 'Base64url-encoded random challenge (16 bytes)',
    username        VARCHAR(256)    NOT NULL,
    expires_at      DATETIME(3)     NOT NULL COMMENT 'Challenge TTL — reject if now > expires_at',
    created_at      DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    PRIMARY KEY (session_id),
    INDEX idx_challenge_sessions_expires_at (expires_at)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Pending WebAuthn ceremony challenge sessions (short-lived)';
