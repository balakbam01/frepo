package com.example.fido2.adapter.in.web.dto;

/** Response for {@code POST /api/v1/registration/complete}. */
public class RegistrationCompleteResponse {

    private boolean success;
    private String credentialId;
    private String message;

    public RegistrationCompleteResponse() {}

    public RegistrationCompleteResponse(boolean success, String credentialId) {
        this.success      = success;
        this.credentialId = credentialId;
        this.message      = success ? "Registration successful" : "Registration failed";
    }

    public boolean isSuccess() { return success; }
    public void setSuccess(boolean success) { this.success = success; }

    public String getCredentialId() { return credentialId; }
    public void setCredentialId(String credentialId) { this.credentialId = credentialId; }

    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }
}
