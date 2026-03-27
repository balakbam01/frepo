package com.example.fido2.adapter.in.web.dto;

import jakarta.validation.constraints.NotBlank;

import java.util.Collections;
import java.util.List;

/**
 * Request body for {@code POST /api/v1/registration/complete}.
 * All binary fields are base64url-encoded strings (no padding).
 */
public class RegistrationCompleteRequest {

    @NotBlank(message = "sessionId is required")
    private String sessionId;

    /** base64url credential ID from {@code PublicKeyCredential.id}. */
    @NotBlank(message = "credentialId is required")
    private String credentialId;

    /** base64url attestationObject from {@code AuthenticatorAttestationResponse}. */
    @NotBlank(message = "attestationObject is required")
    private String attestationObject;

    /** base64url clientDataJSON from {@code AuthenticatorAttestationResponse}. */
    @NotBlank(message = "clientDataJSON is required")
    private String clientDataJSON;

    /** Optional client extension JSON (may be null or omitted). */
    private String clientExtensionsJSON;

    /** Transport hints from {@code AuthenticatorAttestationResponse.getTransports()}. */
    private List<String> transports = Collections.emptyList();

    public String getSessionId() { return sessionId; }
    public void setSessionId(String sessionId) { this.sessionId = sessionId; }

    public String getCredentialId() { return credentialId; }
    public void setCredentialId(String credentialId) { this.credentialId = credentialId; }

    public String getAttestationObject() { return attestationObject; }
    public void setAttestationObject(String attestationObject) { this.attestationObject = attestationObject; }

    public String getClientDataJSON() { return clientDataJSON; }
    public void setClientDataJSON(String clientDataJSON) { this.clientDataJSON = clientDataJSON; }

    public String getClientExtensionsJSON() { return clientExtensionsJSON; }
    public void setClientExtensionsJSON(String clientExtensionsJSON) { this.clientExtensionsJSON = clientExtensionsJSON; }

    public List<String> getTransports() { return transports; }
    public void setTransports(List<String> transports) {
        this.transports = transports != null ? transports : Collections.emptyList();
    }
}
