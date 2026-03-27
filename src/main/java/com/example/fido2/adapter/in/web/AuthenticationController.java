package com.example.fido2.adapter.in.web;

import com.example.fido2.adapter.in.web.dto.AuthenticationCompleteRequest;
import com.example.fido2.adapter.in.web.dto.AuthenticationCompleteResponse;
import com.example.fido2.adapter.in.web.dto.AuthenticationInitRequest;
import com.example.fido2.adapter.in.web.dto.AuthenticationInitResponse;
import com.example.fido2.adapter.in.web.filter.FidoBasicAuthFilter;
import com.example.fido2.application.port.in.CompleteAuthenticationUseCase;
import com.example.fido2.application.port.in.InitiateAuthenticationUseCase;
import com.example.fido2.domain.model.RpConfig;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

/**
 * REST controller for the FIDO2 authentication ceremony.
 *
 * <p>Endpoints:
 * <ul>
 *   <li>{@code POST /api/v1/authentication/initiate} — start ceremony, get request options</li>
 *   <li>{@code POST /api/v1/authentication/complete} — submit assertion, verify identity</li>
 * </ul>
 *
 * <p>The authenticated {@link RpConfig} is injected by {@code FidoBasicAuthFilter} as a
 * request attribute before this controller is invoked.
 */
@RestController
@RequestMapping("/api/v1/authentication")
public class AuthenticationController {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationController.class);

    private final InitiateAuthenticationUseCase initiateAuthenticationUseCase;
    private final CompleteAuthenticationUseCase completeAuthenticationUseCase;

    public AuthenticationController(InitiateAuthenticationUseCase initiateAuthenticationUseCase,
                                     CompleteAuthenticationUseCase completeAuthenticationUseCase) {
        this.initiateAuthenticationUseCase = initiateAuthenticationUseCase;
        this.completeAuthenticationUseCase = completeAuthenticationUseCase;
    }

    /**
     * Initiates a FIDO2 authentication ceremony.
     *
     * @return {@code PublicKeyCredentialRequestOptions} for the browser
     */
    @PostMapping("/initiate")
    public ResponseEntity<AuthenticationInitResponse> initiate(
            @Valid @RequestBody AuthenticationInitRequest request,
            @RequestHeader(value = "X-Correlation-Id", required = false) String correlationId,
            HttpServletRequest httpRequest) {

        RpConfig rpConfig = (RpConfig) httpRequest.getAttribute(FidoBasicAuthFilter.RP_CONFIG_ATTR);
        setupMdc(correlationId, request.getUsername(), rpConfig.getRpId());
        try {
            log.info("POST /api/v1/authentication/initiate username='{}', rpId='{}'",
                    request.getUsername(), rpConfig.getRpId());
            AuthenticationInitResponse response = initiateAuthenticationUseCase
                    .initiateAuthentication(request.getUsername(), rpConfig);
            log.debug("Authentication initiation response: sessionId='{}'", response.getSessionId());
            return ResponseEntity.ok(response);
        } finally {
            MDC.clear();
        }
    }

    /**
     * Completes a FIDO2 authentication ceremony.
     *
     * @return authenticated username on success
     */
    @PostMapping("/complete")
    public ResponseEntity<AuthenticationCompleteResponse> complete(
            @Valid @RequestBody AuthenticationCompleteRequest request,
            @RequestHeader(value = "X-Correlation-Id", required = false) String correlationId,
            HttpServletRequest httpRequest) {

        RpConfig rpConfig = (RpConfig) httpRequest.getAttribute(FidoBasicAuthFilter.RP_CONFIG_ATTR);
        setupMdc(correlationId, null, rpConfig.getRpId());
        try {
            log.info("POST /api/v1/authentication/complete sessionId='{}', rpId='{}'",
                    request.getSessionId(), rpConfig.getRpId());
            AuthenticationCompleteResponse response = completeAuthenticationUseCase
                    .completeAuthentication(request.getSessionId(), request, rpConfig.getRpId());
            return ResponseEntity.ok(response);
        } finally {
            MDC.clear();
        }
    }

    private void setupMdc(String correlationId, String username, String rpId) {
        MDC.put("correlationId", correlationId != null ? correlationId : UUID.randomUUID().toString());
        MDC.put("rpId", rpId);
        if (username != null) {
            MDC.put("username", username);
        }
    }
}
