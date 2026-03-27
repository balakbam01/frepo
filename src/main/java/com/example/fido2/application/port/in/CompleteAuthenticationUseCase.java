package com.example.fido2.application.port.in;

import com.example.fido2.adapter.in.web.dto.AuthenticationCompleteRequest;
import com.example.fido2.adapter.in.web.dto.AuthenticationCompleteResponse;

/**
 * Driving port (input) — finishes a FIDO2 authentication ceremony.
 */
public interface CompleteAuthenticationUseCase {

    /**
     * @param sessionId         unique ID of the challenge session created during initiation
     * @param request           assertion response from the browser
     * @param authenticatedRpId the RP ID resolved from the Authorization header
     * @return result indicating success and the authenticated username
     */
    AuthenticationCompleteResponse completeAuthentication(String sessionId,
                                                          AuthenticationCompleteRequest request,
                                                          String authenticatedRpId);
}
