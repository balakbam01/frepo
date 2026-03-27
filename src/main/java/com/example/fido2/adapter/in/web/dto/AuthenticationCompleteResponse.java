package com.example.fido2.adapter.in.web.dto;

/** Response for {@code POST /api/v1/authentication/complete}. */
public class AuthenticationCompleteResponse {

    private boolean success;
    private String username;
    private String message;

    public AuthenticationCompleteResponse() {}

    public AuthenticationCompleteResponse(boolean success, String username) {
        this.success  = success;
        this.username = username;
        this.message  = success ? "Authentication successful" : "Authentication failed";
    }

    public boolean isSuccess() { return success; }
    public void setSuccess(boolean success) { this.success = success; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }
}
