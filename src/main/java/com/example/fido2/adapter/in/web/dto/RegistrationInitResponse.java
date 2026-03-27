package com.example.fido2.adapter.in.web.dto;

import java.util.List;

/**
 * Response for {@code POST /api/v1/registration/initiate}.
 *
 * <p>Contains the {@code PublicKeyCredentialCreationOptions} fields that the browser
 * needs to call {@code navigator.credentials.create()}, plus the {@code sessionId}
 * used to correlate the subsequent complete request.
 */
public class RegistrationInitResponse {

    /** Opaque session ID — must be sent back in the complete request. */
    private String sessionId;

    // ── PublicKeyCredentialCreationOptions fields ─────────────────────────────

    /** Base64url-encoded challenge bytes. */
    private String challenge;

    /** Relying Party info. */
    private RpInfo rp;

    /** User info. */
    private UserInfo user;

    /** Acceptable public key algorithms. */
    private List<PubKeyCredParam> pubKeyCredParams;

    /** Credential IDs to exclude (already-registered credentials for this user). */
    private List<CredentialDescriptorDto> excludeCredentials;

    /** Ceremony timeout in milliseconds. */
    private long timeout;

    /** Attestation conveyance preference — "none" for privacy-preserving mode. */
    private String attestation = "none";

    // ── Nested types ──────────────────────────────────────────────────────────

    public static class RpInfo {
        private String id;
        private String name;

        public RpInfo() {}
        public RpInfo(String id, String name) { this.id = id; this.name = name; }

        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
    }

    public static class UserInfo {
        /** Base64url-encoded user handle. */
        private String id;
        private String name;
        private String displayName;

        public UserInfo() {}
        public UserInfo(String id, String name, String displayName) {
            this.id = id; this.name = name; this.displayName = displayName;
        }

        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getDisplayName() { return displayName; }
        public void setDisplayName(String displayName) { this.displayName = displayName; }
    }

    public static class PubKeyCredParam {
        private String type = "public-key";
        private long alg;

        public PubKeyCredParam() {}
        public PubKeyCredParam(long alg) { this.alg = alg; }

        public String getType() { return type; }
        public void setType(String type) { this.type = type; }
        public long getAlg() { return alg; }
        public void setAlg(long alg) { this.alg = alg; }
    }

    // ── Builder ───────────────────────────────────────────────────────────────

    public static Builder builder() { return new Builder(); }

    public static final class Builder {
        private final RegistrationInitResponse r = new RegistrationInitResponse();

        public Builder sessionId(String v)                          { r.sessionId = v; return this; }
        public Builder challenge(String v)                          { r.challenge = v; return this; }
        public Builder rp(RpInfo v)                                 { r.rp = v; return this; }
        public Builder user(UserInfo v)                             { r.user = v; return this; }
        public Builder pubKeyCredParams(List<PubKeyCredParam> v)    { r.pubKeyCredParams = v; return this; }
        public Builder excludeCredentials(List<CredentialDescriptorDto> v) { r.excludeCredentials = v; return this; }
        public Builder timeout(long v)                              { r.timeout = v; return this; }
        public Builder attestation(String v)                        { r.attestation = v; return this; }
        public RegistrationInitResponse build()                     { return r; }
    }

    // ── Getters / Setters ─────────────────────────────────────────────────────

    public String getSessionId() { return sessionId; }
    public void setSessionId(String sessionId) { this.sessionId = sessionId; }

    public String getChallenge() { return challenge; }
    public void setChallenge(String challenge) { this.challenge = challenge; }

    public RpInfo getRp() { return rp; }
    public void setRp(RpInfo rp) { this.rp = rp; }

    public UserInfo getUser() { return user; }
    public void setUser(UserInfo user) { this.user = user; }

    public List<PubKeyCredParam> getPubKeyCredParams() { return pubKeyCredParams; }
    public void setPubKeyCredParams(List<PubKeyCredParam> pubKeyCredParams) { this.pubKeyCredParams = pubKeyCredParams; }

    public List<CredentialDescriptorDto> getExcludeCredentials() { return excludeCredentials; }
    public void setExcludeCredentials(List<CredentialDescriptorDto> excludeCredentials) { this.excludeCredentials = excludeCredentials; }

    public long getTimeout() { return timeout; }
    public void setTimeout(long timeout) { this.timeout = timeout; }

    public String getAttestation() { return attestation; }
    public void setAttestation(String attestation) { this.attestation = attestation; }
}
