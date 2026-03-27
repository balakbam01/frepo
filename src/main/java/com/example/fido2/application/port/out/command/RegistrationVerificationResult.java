package com.example.fido2.application.port.out.command;

import java.util.Set;

/**
 * Result of a successful FIDO2 registration ceremony validation.
 * Contains all data that must be persisted as the new credential.
 */
public record RegistrationVerificationResult(
        /** Raw credential ID bytes extracted from the authenticator data. */
        byte[] credentialId,

        /** CBOR-serialised {@code AttestedCredentialData} for storage. Contains the public key. */
        byte[] attestedCredentialDataBytes,

        /** Initial sign count from the authenticator (typically 0 at registration). */
        long signCount,

        /** Transport hints reported by the authenticator. */
        Set<String> transports
) {}
