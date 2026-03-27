package com.example.fido2.application.port.out;

import com.example.fido2.application.port.out.command.AuthenticationVerificationCommand;
import com.example.fido2.application.port.out.command.RegistrationVerificationCommand;
import com.example.fido2.application.port.out.command.RegistrationVerificationResult;

/**
 * Driven port (output) — FIDO2 ceremony validation contract.
 *
 * <p>Decouples the application service from the concrete WebAuthn4J library.
 * The implementation ({@code WebAuthnManagerAdapter}) lives in {@code adapter/out/webauthn}
 * and is the sole place that imports WebAuthn4J classes.
 */
public interface Fido2ValidationPort {

    /**
     * Validates a registration ceremony response and returns the extracted credential data.
     *
     * @param command all raw bytes and session context needed for validation
     * @return extracted credential data to be persisted
     * @throws com.example.fido2.domain.exception.RegistrationFailedException on any validation error
     */
    RegistrationVerificationResult verifyRegistration(RegistrationVerificationCommand command);

    /**
     * Validates an authentication ceremony response and returns the new sign count.
     *
     * @param command all raw bytes, stored credential data, and session context
     * @return the new sign count from the authenticator — must be persisted to detect cloning
     * @throws com.example.fido2.domain.exception.AuthenticationFailedException on any validation error
     */
    long verifyAuthentication(AuthenticationVerificationCommand command);
}
