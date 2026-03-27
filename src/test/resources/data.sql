-- Seed data for integration tests (H2 in-memory DB)
-- Authorization header for tests: Basic base64("localhost:fido123") = "Basic bG9jYWxob3N0OmZpZG8xMjM="
INSERT INTO rp_config (rp_id, rp_name, origin, challenge_ttl_seconds, rp_password, active, created_at, updated_at)
-- origin is a comma-separated list of allowed origins
VALUES ('localhost', 'FIDO2 Test', 'http://localhost:8080,http://localhost:3000', 180, 'fido123', TRUE, CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP());
