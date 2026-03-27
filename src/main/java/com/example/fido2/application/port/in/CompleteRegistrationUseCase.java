package com.example.fido2.application.port.in;

import com.example.fido2.adapter.in.web.dto.RegistrationCompleteRequest;
import com.example.fido2.adapter.in.web.dto.RegistrationCompleteResponse;

/**
 * Driving port (input) — finishes a FIDO2 registration ceremony.
 */
public interface CompleteRegistrationUseCase {

    /**
     * @param sessionId          unique ID of the challenge session created during initiation
     * @param request            attestation response from the browser
     * @param authenticatedRpId  the RP ID resolved from the Authorization header — must match
     *                           the session's RP ID (guards against cross-RP session injection)
     * @return result containing the new credential ID on success
     */
    RegistrationCompleteResponse completeRegistration(String sessionId,
                                                      RegistrationCompleteRequest request,
                                                      String authenticatedRpId);
}
