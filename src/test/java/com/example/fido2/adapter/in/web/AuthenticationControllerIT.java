package com.example.fido2.adapter.in.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for the authentication REST endpoints.
 *
 * <p>All requests carry {@code Authorization: Basic bG9jYWxob3N0OmZpZG8xMjM=}
 * which decodes to {@code localhost:fido123} (matching the test DB seed in data.sql).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
class AuthenticationControllerIT {

    /** Base64(localhost:fido123) */
    private static final String AUTH_HEADER = "Basic bG9jYWxob3N0OmZpZG8xMjM=";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void initiateAuthentication_shouldReturn401WhenNoAuthHeader() throws Exception {
        String body = objectMapper.writeValueAsString(Map.of("username", "nobody@example.com"));

        mockMvc.perform(post("/api/v1/authentication/initiate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void initiateAuthentication_shouldReturn404ForUnknownUser() throws Exception {
        String body = objectMapper.writeValueAsString(Map.of("username", "nobody@example.com"));

        mockMvc.perform(post("/api/v1/authentication/initiate")
                        .header("Authorization", AUTH_HEADER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isNotFound());
    }

    @Test
    void initiateAuthentication_shouldReturn400WhenUsernameBlank() throws Exception {
        mockMvc.perform(post("/api/v1/authentication/initiate")
                        .header("Authorization", AUTH_HEADER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.title").value("Validation Failed"));
    }

    @Test
    void completeAuthentication_shouldReturn400WithInvalidSessionId() throws Exception {
        String body = objectMapper.writeValueAsString(Map.of(
                "sessionId", "bad-session-id",
                "credentialId", "dGVzdA",
                "authenticatorData", "dGVzdA",
                "clientDataJSON", "dGVzdA",
                "signature", "dGVzdA"
        ));

        mockMvc.perform(post("/api/v1/authentication/complete")
                        .header("Authorization", AUTH_HEADER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest());
    }
}
