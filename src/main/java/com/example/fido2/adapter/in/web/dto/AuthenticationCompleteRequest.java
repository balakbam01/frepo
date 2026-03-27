package com.example.fido2.adapter.in.web.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Request body for {@code POST /api/v1/authentication/complete}.
 * All binary fields are base64url-encoded strings (no padding).
 */
public class AuthenticationCompleteRequest {

    @NotBlank(message = "sessionId is required")
    private String sessionId;

    /** base64url credential ID from {@code PublicKeyCredential.id}. */
    @NotBlank(message = "credentialId is required")
    private String credentialId;

    /** base64url authenticatorData from {@code AuthenticatorAssertionResponse}. */
    @NotBlank(message = "authenticatorData is required")
    private String authenticatorData;

    /** base64url clientDataJSON from {@code AuthenticatorAssertionResponse}. */
    @NotBlank(message = "clientDataJSON is required")
    private String clientDataJSON;

    /** base64url signature from {@code AuthenticatorAssertionResponse}. */
    @NotBlank(message = "signature is required")
    private String signature;

    /** base64url userHandle (may be null for non-resident keys). */
    private String userHandle;

    /** Optional client extension JSON (may be null). */
    private String clientExtensionsJSON;

    public String getSessionId() { return sessionId; }
    public void setSessionId(String sessionId) { this.sessionId = sessionId; }

    public String getCredentialId() { return credentialId; }
    public void setCredentialId(String credentialId) { this.credentialId = credentialId; }

    public String getAuthenticatorData() { return authenticatorData; }
    public void setAuthenticatorData(String authenticatorData) { this.authenticatorData = authenticatorData; }

    public String getClientDataJSON() { return clientDataJSON; }
    public void setClientDataJSON(String clientDataJSON) { this.clientDataJSON = clientDataJSON; }

    public String getSignature() { return signature; }
    public void setSignature(String signature) { this.signature = signature; }

    public String getUserHandle() { return userHandle; }
    public void setUserHandle(String userHandle) { this.userHandle = userHandle; }

    public String getClientExtensionsJSON() { return clientExtensionsJSON; }
    public void setClientExtensionsJSON(String clientExtensionsJSON) { this.clientExtensionsJSON = clientExtensionsJSON; }
}
