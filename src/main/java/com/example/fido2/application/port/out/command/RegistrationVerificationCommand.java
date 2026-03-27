package com.example.fido2.application.port.out.command;

import java.util.Set;

/**
 * Command object carrying the raw registration ceremony data to the FIDO2 validation port.
 * All binary fields are base64url-encoded strings as received from the browser.
 */
public record RegistrationVerificationCommand(
        /** base64url-encoded clientDataJSON from the authenticator response. */
        String clientDataJSON,

        /** base64url-encoded attestationObject from the authenticator response. */
        String attestationObject,

        /** Optional client extension JSON (may be null). */
        String clientExtensionsJSON,

        /** Transport hints as reported by the authenticator (e.g. "internal", "usb"). */
        Set<String> transports,

        /** Raw challenge bytes stored at session initiation. */
        byte[] challengeBytes,

        /**
         * Set of allowed origins for this RP (e.g. {"http://localhost:8080", "https://app.example.com"}).
         * The browser-supplied origin in clientDataJSON must match one of these exactly.
         */
        Set<String> rpOrigins,

        /** Relying Party ID (e.g. "localhost"). */
        String rpId
) {}
