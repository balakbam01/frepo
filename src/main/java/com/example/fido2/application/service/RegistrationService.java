package com.example.fido2.application.service;

import com.example.fido2.adapter.in.web.dto.CredentialDescriptorDto;
import com.example.fido2.adapter.in.web.dto.RegistrationCompleteRequest;
import com.example.fido2.adapter.in.web.dto.RegistrationCompleteResponse;
import com.example.fido2.adapter.in.web.dto.RegistrationInitResponse;
import com.example.fido2.application.port.in.CompleteRegistrationUseCase;
import com.example.fido2.application.port.in.InitiateRegistrationUseCase;
import com.example.fido2.application.port.out.ChallengeStore;
import com.example.fido2.application.port.out.CredentialRepository;
import com.example.fido2.application.port.out.Fido2ValidationPort;
import com.example.fido2.application.port.out.RpConfigRepository;
import com.example.fido2.application.port.out.UserRepository;
import com.example.fido2.application.port.out.command.RegistrationVerificationCommand;
import com.example.fido2.application.port.out.command.RegistrationVerificationResult;
import com.example.fido2.domain.exception.ChallengeNotFoundException;
import com.example.fido2.domain.exception.RegistrationFailedException;
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
import java.util.HashSet;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class RegistrationService implements InitiateRegistrationUseCase, CompleteRegistrationUseCase {

    private static final Logger log = LoggerFactory.getLogger(RegistrationService.class);
    private static final long TIMEOUT_MS = 60_000L;

    private final Fido2ValidationPort  fido2ValidationPort;
    private final CredentialRepository credentialRepository;
    private final ChallengeStore       challengeStore;
    private final UserRepository       userRepository;
    private final RpConfigRepository   rpConfigRepository;

    public RegistrationService(Fido2ValidationPort fido2ValidationPort,
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

    // ── InitiateRegistrationUseCase ───────────────────────────────────────────

    @Override
    public RegistrationInitResponse initiateRegistration(String username,
                                                          String displayName,
                                                          RpConfig rpConfig) {
        log.info("Initiating registration: username='{}', rpId='{}'", username, rpConfig.getRpId());

        User user = userRepository.findOrCreate(username, displayName);
        log.debug("User resolved: {}", user);

        DefaultChallenge challenge = new DefaultChallenge();
        String sessionId = UUID.randomUUID().toString();

        Instant expiresAt = Instant.now().plus(rpConfig.getChallengeTtlSeconds(), ChronoUnit.SECONDS);
        challengeStore.store(new ChallengeSession(
                sessionId, challenge.getValue(), username, rpConfig.getRpId(), expiresAt));
        log.debug("Challenge session stored: sessionId='{}', rpId='{}'", sessionId, rpConfig.getRpId());

        List<Credential> existing = credentialRepository.findByUserId(user.getUserId(), rpConfig.getRpId());
        List<CredentialDescriptorDto> excludeCredentials = existing.stream()
                .map(c -> new CredentialDescriptorDto(c.getCredentialId().toBase64Url(), List.copyOf(c.getTransports())))
                .collect(Collectors.toList());
        log.debug("Excluding {} credential(s) for rpId='{}'", excludeCredentials.size(), rpConfig.getRpId());

        String challengeB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(challenge.getValue());
        String userIdB64    = Base64.getUrlEncoder().withoutPadding().encodeToString(user.getUserId().getValue());

        RegistrationInitResponse response = RegistrationInitResponse.builder()
                .sessionId(sessionId)
                .challenge(challengeB64)
                .rp(new RegistrationInitResponse.RpInfo(rpConfig.getRpId(), rpConfig.getRpName()))
                .user(new RegistrationInitResponse.UserInfo(userIdB64, user.getUsername(), user.getDisplayName()))
                .pubKeyCredParams(List.of(
                        new RegistrationInitResponse.PubKeyCredParam(-7L),
                        new RegistrationInitResponse.PubKeyCredParam(-257L)))
                .excludeCredentials(excludeCredentials)
                .timeout(TIMEOUT_MS)
                .attestation("none")
                .build();

        log.info("Registration initiation OK: username='{}', rpId='{}', sessionId='{}'",
                username, rpConfig.getRpId(), sessionId);
        return response;
    }

    // ── CompleteRegistrationUseCase ───────────────────────────────────────────

    @Override
    public RegistrationCompleteResponse completeRegistration(String sessionId,
                                                              RegistrationCompleteRequest request,
                                                              String authenticatedRpId) {
        log.info("Completing registration: sessionId='{}', authenticatedRpId='{}'", sessionId, authenticatedRpId);

        ChallengeSession session = challengeStore.findAndRemove(sessionId)
                .orElseThrow(() -> {
                    log.warn("Challenge session not found: sessionId='{}'", sessionId);
                    return new ChallengeNotFoundException("Challenge session not found: " + sessionId);
                });

        if (session.isExpired()) {
            log.warn("Challenge session expired: sessionId='{}'", sessionId);
            throw new ChallengeNotFoundException("Challenge session expired: " + sessionId);
        }

        // Guard: the session must belong to the RP that authenticated this request
        if (!session.getRpId().equals(authenticatedRpId)) {
            log.warn("RP mismatch: session.rpId='{}', authenticated='{}'",
                    session.getRpId(), authenticatedRpId);
            throw new RegistrationFailedException("Session does not belong to the authenticated RP");
        }

        // Load the full RP config for this session (needed for origin/rpId validation in WebAuthn4J)
        RpConfig rpConfig = rpConfigRepository.findActiveByRpId(session.getRpId())
                .orElseThrow(() -> new RegistrationFailedException(
                        "RP configuration not found for rpId: " + session.getRpId()));

        User user = userRepository.findOrCreate(session.getUsername(), session.getUsername());

        RegistrationVerificationCommand command = new RegistrationVerificationCommand(
                request.getClientDataJSON(),
                request.getAttestationObject(),
                request.getClientExtensionsJSON(),
                new HashSet<>(request.getTransports()),
                session.getChallengeBytes(),
                rpConfig.getOrigins(),
                rpConfig.getRpId()
        );

        log.debug("Delegating registration verification to Fido2ValidationPort");
        RegistrationVerificationResult result = fido2ValidationPort.verifyRegistration(command);

        Credential credential = Credential.builder()
                .credentialId(new CredentialId(result.credentialId()))
                .userId(user.getUserId())
                .username(user.getUsername())
                .rpId(rpConfig.getRpId())
                .attestedCredentialDataBytes(result.attestedCredentialDataBytes())
                .signCount(result.signCount())
                .transports(result.transports())
                .registeredAt(Instant.now())
                .build();

        credentialRepository.save(credential);

        String credIdB64 = credential.getCredentialId().toBase64Url();
        log.info("Registration complete: username='{}', rpId='{}', credentialId='{}'",
                user.getUsername(), rpConfig.getRpId(), credIdB64);
        return new RegistrationCompleteResponse(true, credIdB64);
    }
}
