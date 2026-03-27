package com.example.fido2.config;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.util.ObjectConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Spring configuration for WebAuthn4J beans.
 *
 * <p>For development/testing, {@link WebAuthnManager#createNonStrictWebAuthnManager()} is used.
 * It skips attestation certificate chain validation (useful when working with platform
 * authenticators or virtual authenticators during development).
 *
 * <p><strong>Production upgrade:</strong> Replace with the full constructor that wires
 * {@code PackedAttestationStatementValidator}, {@code TpmAttestationStatementValidator}, etc.,
 * backed by a {@code FidoMds3MetadataStatementRepository} from {@code webauthn4j-metadata}.
 */
@Configuration
public class WebAuthnConfig {

    private static final Logger log = LoggerFactory.getLogger(WebAuthnConfig.class);

    /**
     * Shared {@link ObjectConverter} used for CBOR/JSON serialisation inside WebAuthn4J.
     * Declare as a bean so the same Jackson {@code CBORMapper} instance is shared between
     * {@link WebAuthnManager} and {@code AttestedCredentialDataConverter}.
     */
    @Bean
    public ObjectConverter objectConverter() {
        log.debug("Creating shared WebAuthn4J ObjectConverter bean");
        return new ObjectConverter();
    }

    /**
     * Non-strict WebAuthnManager — attestation statement validation is skipped.
     * Safe for development; swap for a production-grade instance before going live.
     */
    @Bean
    public WebAuthnManager webAuthnManager(ObjectConverter objectConverter) {
        log.info("Initialising WebAuthnManager (non-strict / development mode)");
        return WebAuthnManager.createNonStrictWebAuthnManager(objectConverter);
    }
}
