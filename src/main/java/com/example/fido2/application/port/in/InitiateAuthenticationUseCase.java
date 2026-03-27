package com.example.fido2.application.port.in;

import com.example.fido2.adapter.in.web.dto.AuthenticationInitResponse;
import com.example.fido2.domain.model.RpConfig;

/**
 * Driving port (input) — starts a FIDO2 authentication ceremony for a specific RP.
 */
public interface InitiateAuthenticationUseCase {

    /**
     * @param username  the account identifier of the user attempting to authenticate
     * @param rpConfig  the Relying Party configuration resolved from the auth header
     * @return {@code PublicKeyCredentialRequestOptions} to pass to {@code navigator.credentials.get()}
     */
    AuthenticationInitResponse initiateAuthentication(String username, RpConfig rpConfig);
}
