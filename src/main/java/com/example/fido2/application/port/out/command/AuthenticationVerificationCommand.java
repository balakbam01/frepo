package com.example.fido2.application.port.out.command;

/**
 * Command object carrying the raw authentication ceremony data to the FIDO2 validation port.
 * All binary fields are base64url-encoded strings as received from the browser.
 */
import java.util.Set;

public record AuthenticationVerificationCommand(
        /** base64url-encoded credential ID from the assertion. */
        String credentialId,

        /** base64url-encoded authenticatorData from the assertion response. */
        String authenticatorData,

        /** base64url-encoded clientDataJSON from the assertion response. */
        String clientDataJSON,

        /** base64url-encoded signature from the assertion response. */
        String signature,

        /** base64url-encoded userHandle (may be null for non-resident keys). */
        String userHandle,

        /** Optional client extension JSON (may be null). */
        String clientExtensionsJSON,

        /** Raw challenge bytes stored at session initiation. */
        byte[] challengeBytes,

        /** CBOR-serialised AttestedCredentialData retrieved from the credential store. */
        byte[] storedAttestedCredentialDataBytes,

        /** Sign count stored for this credential — used for cloning detection. */
        long storedSignCount,

        /**
         * Set of allowed origins for this RP (e.g. {"http://localhost:8080", "https://app.example.com"}).
         * The browser-supplied origin in clientDataJSON must match one of these exactly.
         */
        Set<String> rpOrigins,

        /** Relying Party ID. */
        String rpId
) {}
