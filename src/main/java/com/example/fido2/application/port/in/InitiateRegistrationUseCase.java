package com.example.fido2.application.port.in;

import com.example.fido2.adapter.in.web.dto.RegistrationInitResponse;
import com.example.fido2.domain.model.RpConfig;

/**
 * Driving port (input) — starts a FIDO2 registration ceremony for a specific RP.
 */
public interface InitiateRegistrationUseCase {

    /**
     * @param username    unique account identifier (e.g. email address)
     * @param displayName human-readable name for display in authenticator prompts
     * @param rpConfig    the Relying Party configuration resolved from the auth header
     * @return {@code PublicKeyCredentialCreationOptions} to pass to {@code navigator.credentials.create()}
     */
    RegistrationInitResponse initiateRegistration(String username, String displayName, RpConfig rpConfig);
}
