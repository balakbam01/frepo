package com.example.fido2.adapter.in.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Request body for {@code POST /api/v1/registration/initiate}. */
public class RegistrationInitRequest {

    @NotBlank(message = "username is required")
    @Size(max = 256)
    private String username;

    @Size(max = 256)
    private String displayName;

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getDisplayName() { return displayName != null ? displayName : username; }
    public void setDisplayName(String displayName) { this.displayName = displayName; }
}
