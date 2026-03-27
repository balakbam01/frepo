package com.example.fido2.adapter.in.web;

import com.example.fido2.adapter.in.web.dto.RegistrationCompleteRequest;
import com.example.fido2.adapter.in.web.dto.RegistrationCompleteResponse;
import com.example.fido2.adapter.in.web.dto.RegistrationInitRequest;
import com.example.fido2.adapter.in.web.dto.RegistrationInitResponse;
import com.example.fido2.adapter.in.web.filter.FidoBasicAuthFilter;
import com.example.fido2.application.port.in.CompleteRegistrationUseCase;
import com.example.fido2.application.port.in.InitiateRegistrationUseCase;
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
 * REST controller for the FIDO2 registration ceremony.
 *
 * <p>Endpoints:
 * <ul>
 *   <li>{@code POST /api/v1/registration/initiate} — start ceremony, get creation options</li>
 *   <li>{@code POST /api/v1/registration/complete} — submit attestation, persist credential</li>
 * </ul>
 *
 * <p>The authenticated {@link RpConfig} is injected by {@code FidoBasicAuthFilter} as a
 * request attribute before this controller is invoked.
 */
@RestController
@RequestMapping("/api/v1/registration")
public class RegistrationController {

    private static final Logger log = LoggerFactory.getLogger(RegistrationController.class);

    private final InitiateRegistrationUseCase initiateRegistrationUseCase;
    private final CompleteRegistrationUseCase completeRegistrationUseCase;

    public RegistrationController(InitiateRegistrationUseCase initiateRegistrationUseCase,
                                   CompleteRegistrationUseCase completeRegistrationUseCase) {
        this.initiateRegistrationUseCase = initiateRegistrationUseCase;
        this.completeRegistrationUseCase = completeRegistrationUseCase;
    }

    /**
     * Initiates a FIDO2 registration ceremony.
     *
     * @return {@code PublicKeyCredentialCreationOptions} for the browser
     */
    @PostMapping("/initiate")
    public ResponseEntity<RegistrationInitResponse> initiate(
            @Valid @RequestBody RegistrationInitRequest request,
            @RequestHeader(value = "X-Correlation-Id", required = false) String correlationId,
            HttpServletRequest httpRequest) {

        RpConfig rpConfig = (RpConfig) httpRequest.getAttribute(FidoBasicAuthFilter.RP_CONFIG_ATTR);
        setupMdc(correlationId, request.getUsername(), rpConfig.getRpId());
        try {
            log.info("POST /api/v1/registration/initiate username='{}', rpId='{}'",
                    request.getUsername(), rpConfig.getRpId());
            RegistrationInitResponse response = initiateRegistrationUseCase
                    .initiateRegistration(request.getUsername(), request.getDisplayName(), rpConfig);
            log.debug("Registration initiation response: sessionId='{}'", response.getSessionId());
            return ResponseEntity.ok(response);
        } finally {
            MDC.clear();
        }
    }

    /**
     * Completes a FIDO2 registration ceremony.
     *
     * @return credential ID of the newly registered authenticator
     */
    @PostMapping("/complete")
    public ResponseEntity<RegistrationCompleteResponse> complete(
            @Valid @RequestBody RegistrationCompleteRequest request,
            @RequestHeader(value = "X-Correlation-Id", required = false) String correlationId,
            HttpServletRequest httpRequest) {

        RpConfig rpConfig = (RpConfig) httpRequest.getAttribute(FidoBasicAuthFilter.RP_CONFIG_ATTR);
        setupMdc(correlationId, null, rpConfig.getRpId());
        try {
            log.info("POST /api/v1/registration/complete sessionId='{}', rpId='{}'",
                    request.getSessionId(), rpConfig.getRpId());
            RegistrationCompleteResponse response = completeRegistrationUseCase
                    .completeRegistration(request.getSessionId(), request, rpConfig.getRpId());
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
