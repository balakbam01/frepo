package com.example.fido2.application.port.out;

import com.example.fido2.domain.model.Credential;
import com.example.fido2.domain.model.CredentialId;
import com.example.fido2.domain.model.UserId;

import java.util.List;
import java.util.Optional;

/**
 * Driven port (output) — persistence contract for {@link Credential} entities.
 *
 * <p>All query methods are scoped to a {@code rpId} to enforce multi-RP isolation:
 * a credential registered with one RP cannot be located or used by another.
 */
public interface CredentialRepository {

    /** Persists a newly registered credential (includes rpId). */
    void save(Credential credential);

    /** Finds a credential by its raw ID, scoped to the given RP. */
    Optional<Credential> findByCredentialId(CredentialId credentialId, String rpId);

    /** Returns all credentials a user has registered with the given RP. */
    List<Credential> findByUserId(UserId userId, String rpId);

    /**
     * Updates the sign count and last-used timestamp after a successful authentication.
     * Scoped to the RP to prevent cross-RP tampering.
     */
    void updateSignCount(CredentialId credentialId, String rpId, long newSignCount);
}
