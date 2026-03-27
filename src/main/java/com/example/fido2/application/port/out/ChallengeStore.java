package com.example.fido2.application.port.out;

import com.example.fido2.domain.model.ChallengeSession;

import java.util.Optional;

/**
 * Driven port (output) — storage contract for pending {@link ChallengeSession} instances.
 *
 * <p>The {@link #findAndRemove(String)} operation MUST be atomic: if the session exists it
 * is returned and immediately deleted in a single operation. This prevents replay attacks
 * where an attacker captures a valid authenticator response and re-submits it.
 */
public interface ChallengeStore {

    /** Stores a new challenge session. Overwrites any existing session with the same ID. */
    void store(ChallengeSession session);

    /**
     * Atomically retrieves and deletes the session for {@code sessionId}.
     *
     * @return the session if present, or {@link Optional#empty()} if not found or already consumed.
     */
    Optional<ChallengeSession> findAndRemove(String sessionId);
}
