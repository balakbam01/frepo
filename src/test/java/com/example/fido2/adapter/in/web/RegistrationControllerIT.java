package com.example.fido2.adapter.in.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for the registration REST endpoints.
 *
 * <p>All requests carry {@code Authorization: Basic bG9jYWxob3N0OmZpZG8xMjM=}
 * which decodes to {@code localhost:fido123} (matching the test DB seed in data.sql).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
class RegistrationControllerIT {

    /** Base64(localhost:fido123) */
    private static final String AUTH_HEADER = "Basic bG9jYWxob3N0OmZpZG8xMjM=";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void initiateRegistration_shouldReturn200WithValidOptions() throws Exception {
        String body = objectMapper.writeValueAsString(Map.of(
                "username", "test@example.com",
                "displayName", "Test User"
        ));

        MvcResult result = mockMvc.perform(post("/api/v1/registration/initiate")
                        .header("Authorization", AUTH_HEADER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.sessionId").isNotEmpty())
                .andExpect(jsonPath("$.challenge").isNotEmpty())
                .andExpect(jsonPath("$.rp.id").value("localhost"))
                .andExpect(jsonPath("$.user.name").value("test@example.com"))
                .andExpect(jsonPath("$.pubKeyCredParams").isArray())
                .andExpect(jsonPath("$.timeout").value(60000))
                .andReturn();

        String responseBody = result.getResponse().getContentAsString();
        Map<?, ?> responseMap = objectMapper.readValue(responseBody, Map.class);

        // Challenge must be a valid base64url string
        String challenge = (String) responseMap.get("challenge");
        assertThat(challenge).isNotNull().isNotEmpty();
        assertThat(challenge).doesNotContain("+", "/", "="); // base64url, no padding
    }

    @Test
    void initiateRegistration_shouldReturn401WhenNoAuthHeader() throws Exception {
        String body = objectMapper.writeValueAsString(Map.of(
                "username", "test@example.com",
                "displayName", "Test User"
        ));

        mockMvc.perform(post("/api/v1/registration/initiate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void initiateRegistration_shouldReturn401WhenWrongPassword() throws Exception {
        // Base64(localhost:wrongpassword)
        String body = objectMapper.writeValueAsString(Map.of(
                "username", "test@example.com",
                "displayName", "Test User"
        ));

        mockMvc.perform(post("/api/v1/registration/initiate")
                        .header("Authorization", "Basic bG9jYWxob3N0Ondyb25ncGFzc3dvcmQ=")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void initiateRegistration_shouldReturn400WhenUsernameBlank() throws Exception {
        mockMvc.perform(post("/api/v1/registration/initiate")
                        .header("Authorization", AUTH_HEADER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.title").value("Validation Failed"));
    }

    @Test
    void initiateRegistration_shouldReturn400WhenBodyMissing() throws Exception {
        mockMvc.perform(post("/api/v1/registration/initiate")
                        .header("Authorization", AUTH_HEADER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void completeRegistration_shouldReturn400WithInvalidSessionId() throws Exception {
        String body = objectMapper.writeValueAsString(Map.of(
                "sessionId", "non-existent-session",
                "credentialId", "dGVzdA",
                "attestationObject", "dGVzdA",
                "clientDataJSON", "dGVzdA"
        ));

        mockMvc.perform(post("/api/v1/registration/complete")
                        .header("Authorization", AUTH_HEADER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest());
    }
}
