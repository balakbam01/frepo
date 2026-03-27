package com.example.fido2.adapter.in.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Request body for {@code POST /api/v1/authentication/initiate}. */
public class AuthenticationInitRequest {

    @NotBlank(message = "username is required")
    @Size(max = 256)
    private String username;

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
}
