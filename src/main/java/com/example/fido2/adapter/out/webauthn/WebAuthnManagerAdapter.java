package com.example.fido2.adapter.out.webauthn;

import com.example.fido2.application.port.out.Fido2ValidationPort;
import com.example.fido2.application.port.out.command.AuthenticationVerificationCommand;
import com.example.fido2.application.port.out.command.RegistrationVerificationCommand;
import com.example.fido2.application.port.out.command.RegistrationVerificationResult;
import com.example.fido2.domain.exception.AuthenticationFailedException;
import com.example.fido2.domain.exception.RegistrationFailedException;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.AuthenticationRequest;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.validator.exception.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Infrastructure adapter that implements {@link Fido2ValidationPort} using WebAuthn4J.
 *
 * <p>This class is the <strong>sole location in the codebase</strong> that imports WebAuthn4J
 * classes. Keeping the library isolated here means swapping the FIDO2 library later requires
 * only changes within this class.
 *
 * <p>The two-step parse-then-validate pattern is intentional: parsing throws
 * {@link DataConversionException} for malformed CBOR/JSON, while validation throws
 * {@link ValidationException} for semantic WebAuthn violations. Distinguishing them
 * produces better error messages and log entries.
 */
@Component
public class WebAuthnManagerAdapter implements Fido2ValidationPort {

    private static final Logger log = LoggerFactory.getLogger(WebAuthnManagerAdapter.class);

    /** Accepted public key algorithms — ES256 (ECDSA P-256) and RS256 (RSA PKCS1 v1.5). */
    private static final List<PublicKeyCredentialParameters> ACCEPTED_PUB_KEY_PARAMS = List.of(
            new PublicKeyCredentialParameters(
                    PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256),
            new PublicKeyCredentialParameters(
                    PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS256)
    );

    private final WebAuthnManager webAuthnManager;

    /**
     * Converts between {@link AttestedCredentialData} objects and their CBOR byte[] form.
     * Must use the same {@link ObjectConverter} instance as the {@link WebAuthnManager}.
     */
    private final AttestedCredentialDataConverter attestedCredentialDataConverter;

    public WebAuthnManagerAdapter(WebAuthnManager webAuthnManager,
                                   ObjectConverter objectConverter) {
        this.webAuthnManager                  = webAuthnManager;
        this.attestedCredentialDataConverter  = new AttestedCredentialDataConverter(objectConverter);
        log.info("WebAuthnManagerAdapter initialised");
    }

    // ── Registration ──────────────────────────────────────────────────────────

    @Override
    public RegistrationVerificationResult verifyRegistration(RegistrationVerificationCommand cmd) {
        log.debug("Verifying registration: rpId='{}', origins='{}'", cmd.rpId(), cmd.rpOrigins());

        // 1. Decode base64url inputs
        byte[] clientDataJSONBytes  = decodeBase64Url(cmd.clientDataJSON(),  "clientDataJSON");
        byte[] attestationObjBytes  = decodeBase64Url(cmd.attestationObject(), "attestationObject");

        // 2. Build the RegistrationRequest (raw bytes only — no validation yet)
        RegistrationRequest registrationRequest = new RegistrationRequest(
                attestationObjBytes,
                clientDataJSONBytes,
                cmd.clientExtensionsJSON(),
                cmd.transports() != null ? new HashSet<>(cmd.transports()) : new HashSet<>()
        );

        // 3. Build the ServerProperty
        //    Origins must match EXACTLY what the browser placed in clientDataJSON.origin
        //    (scheme + host + port, no trailing slash). Multiple origins supported.
        Set<Origin> origins = toOriginSet(cmd.rpOrigins());
        ServerProperty serverProperty = new ServerProperty(
                origins,
                cmd.rpId(),
                new DefaultChallenge(cmd.challengeBytes()),
                null  // tokenBindingId — not used
        );

        // 4. Registration parameters
        RegistrationParameters registrationParameters = new RegistrationParameters(
                serverProperty,
                ACCEPTED_PUB_KEY_PARAMS,
                false,  // userVerificationRequired — set to true to require biometrics/PIN
                true    // userPresenceRequired     — nearly always true per WebAuthn spec
        );

        // 5. Parse (CBOR/JSON decoding — throws DataConversionException on malformed data)
        RegistrationData registrationData;
        try {
            registrationData = webAuthnManager.parse(registrationRequest);
            log.debug("Registration data parsed successfully");
        } catch (DataConversionException e) {
            log.warn("Registration parse failed — malformed data", e);
            throw new RegistrationFailedException("Malformed registration data: " + e.getMessage(), e);
        }

        // 6. Validate (cryptographic and semantic checks — throws ValidationException)
        try {
            webAuthnManager.validate(registrationData, registrationParameters);
            log.debug("Registration validation passed");
        } catch (ValidationException e) {
            log.warn("Registration validation failed: {}", e.getMessage(), e);
            throw new RegistrationFailedException("Registration validation failed: " + e.getMessage(), e);
        }

        // 7. Extract credential data
        //    Navigation path:
        //    RegistrationData -> AttestationObject -> AuthenticatorData -> AttestedCredentialData
        AttestedCredentialData attestedCredentialData = registrationData
                .getAttestationObject()
                .getAuthenticatorData()
                .getAttestedCredentialData();

        if (attestedCredentialData == null) {
            // Should never happen after successful validation, but guard defensively
            throw new RegistrationFailedException("AttestedCredentialData is null after validation");
        }

        byte[] credentialId = attestedCredentialData.getCredentialId();
        long   signCount    = registrationData
                .getAttestationObject()
                .getAuthenticatorData()
                .getSignCount();

        // 8. Serialise AttestedCredentialData to CBOR bytes for storage
        //    AttestedCredentialDataConverter handles the COSE public key serialisation
        byte[] storedBytes = attestedCredentialDataConverter.convert(attestedCredentialData);

        log.info("Registration verified: credentialId='{}', signCount={}",
                Base64.getUrlEncoder().withoutPadding().encodeToString(credentialId), signCount);

        return new RegistrationVerificationResult(
                credentialId,
                storedBytes,
                signCount,
                cmd.transports() != null ? new HashSet<>(cmd.transports()) : new HashSet<>()
        );
    }

    // ── Authentication ────────────────────────────────────────────────────────

    @Override
    public long verifyAuthentication(AuthenticationVerificationCommand cmd) {
        log.debug("Verifying authentication: credentialId='{}', rpId='{}'",
                cmd.credentialId(), cmd.rpId());

        // 1. Decode base64url inputs
        byte[] credentialIdBytes  = decodeBase64Url(cmd.credentialId(),      "credentialId");
        byte[] authenticatorData  = decodeBase64Url(cmd.authenticatorData(),  "authenticatorData");
        byte[] clientDataJSON     = decodeBase64Url(cmd.clientDataJSON(),     "clientDataJSON");
        byte[] signature          = decodeBase64Url(cmd.signature(),          "signature");
        byte[] userHandle         = cmd.userHandle() != null
                ? decodeBase64Url(cmd.userHandle(), "userHandle") : null;

        // 2. Build the AuthenticationRequest
        AuthenticationRequest authRequest = new AuthenticationRequest(
                credentialIdBytes,
                userHandle,
                authenticatorData,
                clientDataJSON,
                cmd.clientExtensionsJSON(),
                signature
        );

        // 3. Reconstruct the stored AttestedCredentialData from CBOR bytes
        AttestedCredentialData storedAttestedCredentialData =
                attestedCredentialDataConverter.convert(cmd.storedAttestedCredentialDataBytes());

        // 4. Build the Authenticator instance
        //    AuthenticatorImpl holds the public key and the stored sign count.
        //    The attestation statement is not needed for authentication validation.
        AuthenticatorImpl authenticator = new AuthenticatorImpl(
                storedAttestedCredentialData,
                null,                        // attestation statement — not needed here
                cmd.storedSignCount()
        );

        // 5. Build the ServerProperty
        Set<Origin> origins = toOriginSet(cmd.rpOrigins());
        ServerProperty serverProperty = new ServerProperty(
                origins,
                cmd.rpId(),
                new DefaultChallenge(cmd.challengeBytes()),
                null  // tokenBindingId
        );

        // 6. Authentication parameters
        //    allowCredentials restricts which credential IDs are accepted
        List<byte[]> allowCredentials = List.of(credentialIdBytes);

        AuthenticationParameters authParameters = new AuthenticationParameters(
                serverProperty,
                authenticator,
                allowCredentials,
                false,  // userVerificationRequired
                true    // userPresenceRequired
        );

        // 7. Parse (throws DataConversionException on malformed data)
        AuthenticationData authData;
        try {
            authData = webAuthnManager.parse(authRequest);
            log.debug("Authentication data parsed successfully");
        } catch (DataConversionException e) {
            log.warn("Authentication parse failed — malformed data", e);
            throw new AuthenticationFailedException("Malformed authentication data: " + e.getMessage(), e);
        }

        // 8. Validate (signature verification, challenge binding, origin check, etc.)
        try {
            webAuthnManager.validate(authData, authParameters);
            log.debug("Authentication validation passed");
        } catch (ValidationException e) {
            log.warn("Authentication validation failed for credentialId='{}': {}",
                    cmd.credentialId(), e.getMessage(), e);
            throw new AuthenticationFailedException(
                    "Authentication validation failed: " + e.getMessage(), e);
        }

        // 9. Extract and return the new sign count
        //    Callers MUST persist this value; a decreasing count indicates authenticator cloning.
        long newSignCount = authData.getAuthenticatorData().getSignCount();

        log.info("Authentication verified: credentialId='{}', previousCount={}, newCount={}",
                cmd.credentialId(), cmd.storedSignCount(), newSignCount);

        return newSignCount;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private Set<Origin> toOriginSet(Set<String> originStrings) {
        return originStrings.stream()
                .map(Origin::new)
                .collect(Collectors.toSet());
    }

    private byte[] decodeBase64Url(String base64url, String fieldName) {
        try {
            return Base64.getUrlDecoder().decode(base64url);
        } catch (IllegalArgumentException e) {
            log.warn("Invalid base64url encoding for field '{}': {}", fieldName, e.getMessage());
            throw new RegistrationFailedException(
                    "Invalid base64url value for field '" + fieldName + "'", e);
        }
    }
}
