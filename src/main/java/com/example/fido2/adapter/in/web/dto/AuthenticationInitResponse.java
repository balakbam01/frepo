package com.example.fido2.adapter.in.web.dto;

import java.util.List;

/**
 * Response for {@code POST /api/v1/authentication/initiate}.
 *
 * <p>Contains the {@code PublicKeyCredentialRequestOptions} fields needed by the browser
 * to call {@code navigator.credentials.get()}.
 */
public class AuthenticationInitResponse {

    /** Opaque session ID — must be sent back in the complete request. */
    private String sessionId;

    /** Base64url-encoded challenge bytes. */
    private String challenge;

    /** Relying Party ID. */
    private String rpId;

    /** Credentials the user has registered — empty list means any credential is accepted. */
    private List<CredentialDescriptorDto> allowCredentials;

    /** Timeout in milliseconds. */
    private long timeout;

    /** User verification requirement: "required", "preferred", or "discouraged". */
    private String userVerification = "preferred";

    public static Builder builder() { return new Builder(); }

    public static final class Builder {
        private final AuthenticationInitResponse r = new AuthenticationInitResponse();

        public Builder sessionId(String v)                           { r.sessionId = v; return this; }
        public Builder challenge(String v)                           { r.challenge = v; return this; }
        public Builder rpId(String v)                                { r.rpId = v; return this; }
        public Builder allowCredentials(List<CredentialDescriptorDto> v) { r.allowCredentials = v; return this; }
        public Builder timeout(long v)                               { r.timeout = v; return this; }
        public Builder userVerification(String v)                    { r.userVerification = v; return this; }
        public AuthenticationInitResponse build()                    { return r; }
    }

    public String getSessionId() { return sessionId; }
    public void setSessionId(String sessionId) { this.sessionId = sessionId; }

    public String getChallenge() { return challenge; }
    public void setChallenge(String challenge) { this.challenge = challenge; }

    public String getRpId() { return rpId; }
    public void setRpId(String rpId) { this.rpId = rpId; }

    public List<CredentialDescriptorDto> getAllowCredentials() { return allowCredentials; }
    public void setAllowCredentials(List<CredentialDescriptorDto> allowCredentials) { this.allowCredentials = allowCredentials; }

    public long getTimeout() { return timeout; }
    public void setTimeout(long timeout) { this.timeout = timeout; }

    public String getUserVerification() { return userVerification; }
    public void setUserVerification(String userVerification) { this.userVerification = userVerification; }
}
