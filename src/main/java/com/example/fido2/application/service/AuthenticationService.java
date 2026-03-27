package com.example.fido2.application.service;

import com.example.fido2.adapter.in.web.dto.AuthenticationCompleteRequest;
import com.example.fido2.adapter.in.web.dto.AuthenticationCompleteResponse;
import com.example.fido2.adapter.in.web.dto.AuthenticationInitResponse;
import com.example.fido2.adapter.in.web.dto.CredentialDescriptorDto;
import com.example.fido2.application.port.in.CompleteAuthenticationUseCase;
import com.example.fido2.application.port.in.InitiateAuthenticationUseCase;
import com.example.fido2.application.port.out.ChallengeStore;
import com.example.fido2.application.port.out.CredentialRepository;
import com.example.fido2.application.port.out.Fido2ValidationPort;
import com.example.fido2.application.port.out.RpConfigRepository;
import com.example.fido2.application.port.out.UserRepository;
import com.example.fido2.application.port.out.command.AuthenticationVerificationCommand;
import com.example.fido2.domain.exception.AuthenticationFailedException;
import com.example.fido2.domain.exception.ChallengeNotFoundException;
import com.example.fido2.domain.exception.CredentialNotFoundException;
import com.example.fido2.domain.exception.UserNotFoundException;
import com.example.fido2.domain.model.ChallengeSession;
import com.example.fido2.domain.model.Credential;
import com.example.fido2.domain.model.CredentialId;
import com.example.fido2.domain.model.RpConfig;
import com.example.fido2.domain.model.User;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class AuthenticationService
        implements InitiateAuthenticationUseCase, CompleteAuthenticationUseCase {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationService.class);
    private static final long TIMEOUT_MS = 60_000L;

    private final Fido2ValidationPort  fido2ValidationPort;
    private final CredentialRepository credentialRepository;
    private final ChallengeStore       challengeStore;
    private final UserRepository       userRepository;
    private final RpConfigRepository   rpConfigRepository;

    public AuthenticationService(Fido2ValidationPort fido2ValidationPort,
                                  CredentialRepository credentialRepository,
                                  ChallengeStore challengeStore,
                                  UserRepository userRepository,
                                  RpConfigRepository rpConfigRepository) {
        this.fido2ValidationPort  = fido2ValidationPort;
        this.credentialRepository = credentialRepository;
        this.challengeStore       = challengeStore;
        this.userRepository       = userRepository;
        this.rpConfigRepository   = rpConfigRepository;
    }

    // ── InitiateAuthenticationUseCase ─────────────────────────────────────────

    @Override
    public AuthenticationInitResponse initiateAuthentication(String username, RpConfig rpConfig) {
        log.info("Initiating authentication: username='{}', rpId='{}'", username, rpConfig.getRpId());

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> {
                    log.warn("User not found: '{}'", username);
                    return new UserNotFoundException("User not found: " + username);
                });

        List<Credential> credentials = credentialRepository.findByUserId(user.getUserId(), rpConfig.getRpId());
        if (credentials.isEmpty()) {
            log.warn("No credentials for user='{}', rpId='{}'", username, rpConfig.getRpId());
            throw new CredentialNotFoundException(
                    "No credentials registered for user '" + username + "' on RP '" + rpConfig.getRpId() + "'");
        }
        log.debug("Found {} credential(s) for user='{}', rpId='{}'",
                credentials.size(), username, rpConfig.getRpId());

        DefaultChallenge challenge  = new DefaultChallenge();
        String           sessionId  = UUID.randomUUID().toString();
        Instant          expiresAt  = Instant.now().plus(rpConfig.getChallengeTtlSeconds(), ChronoUnit.SECONDS);

        challengeStore.store(new ChallengeSession(
                sessionId, challenge.getValue(), username, rpConfig.getRpId(), expiresAt));

        List<CredentialDescriptorDto> allowCredentials = credentials.stream()
                .map(c -> new CredentialDescriptorDto(c.getCredentialId().toBase64Url(), List.copyOf(c.getTransports())))
                .collect(Collectors.toList());

        String challengeB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(challenge.getValue());

        log.info("Authentication initiation OK: username='{}', rpId='{}', sessionId='{}'",
                username, rpConfig.getRpId(), sessionId);
        return AuthenticationInitResponse.builder()
                .sessionId(sessionId)
                .challenge(challengeB64)
                .rpId(rpConfig.getRpId())
                .allowCredentials(allowCredentials)
                .timeout(TIMEOUT_MS)
                .userVerification("preferred")
                .build();
    }

    // ── CompleteAuthenticationUseCase ─────────────────────────────────────────

    @Override
    public AuthenticationCompleteResponse completeAuthentication(String sessionId,
                                                                   AuthenticationCompleteRequest request,
                                                                   String authenticatedRpId) {
        log.info("Completing authentication: sessionId='{}', authenticatedRpId='{}'",
                sessionId, authenticatedRpId);

        ChallengeSession session = challengeStore.findAndRemove(sessionId)
                .orElseThrow(() -> {
                    log.warn("Challenge session not found: '{}'", sessionId);
                    return new ChallengeNotFoundException("Challenge session not found: " + sessionId);
                });

        if (session.isExpired()) {
            log.warn("Challenge session expired: '{}'", sessionId);
            throw new ChallengeNotFoundException("Challenge session expired: " + sessionId);
        }

        if (!session.getRpId().equals(authenticatedRpId)) {
            log.warn("RP mismatch in auth complete: session.rpId='{}', authenticated='{}'",
                    session.getRpId(), authenticatedRpId);
            throw new AuthenticationFailedException("Session does not belong to the authenticated RP");
        }

        RpConfig rpConfig = rpConfigRepository.findActiveByRpId(session.getRpId())
                .orElseThrow(() -> new AuthenticationFailedException(
                        "RP configuration not found: " + session.getRpId()));

        byte[]     credIdBytes      = Base64.getUrlDecoder().decode(request.getCredentialId());
        Credential storedCredential = credentialRepository
                .findByCredentialId(new CredentialId(credIdBytes), rpConfig.getRpId())
                .orElseThrow(() -> {
                    log.warn("Credential not found: '{}' on rpId='{}'",
                            request.getCredentialId(), rpConfig.getRpId());
                    return new CredentialNotFoundException(
                            "Credential not found: " + request.getCredentialId());
                });

        AuthenticationVerificationCommand command = new AuthenticationVerificationCommand(
                request.getCredentialId(),
                request.getAuthenticatorData(),
                request.getClientDataJSON(),
                request.getSignature(),
                request.getUserHandle(),
                request.getClientExtensionsJSON(),
                session.getChallengeBytes(),
                storedCredential.getAttestedCredentialDataBytes(),
                storedCredential.getSignCount(),
                rpConfig.getOrigins(),
                rpConfig.getRpId()
        );

        log.debug("Delegating authentication verification to Fido2ValidationPort");
        long newSignCount = fido2ValidationPort.verifyAuthentication(command);

        credentialRepository.updateSignCount(storedCredential.getCredentialId(), rpConfig.getRpId(), newSignCount);

        log.info("Authentication complete: username='{}', rpId='{}', credentialId='{}'",
                session.getUsername(), rpConfig.getRpId(), request.getCredentialId());
        return new AuthenticationCompleteResponse(true, session.getUsername());
    }
}
