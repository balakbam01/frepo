package com.example.fido2.domain.model;

import java.time.Instant;
import java.util.Objects;

/**
 * Domain value object representing a pending WebAuthn challenge session.
 *
 * <p>A challenge session is created at ceremony initiation (registration or authentication)
 * and consumed (deleted) atomically when the ceremony completes. Consuming on retrieval
 * prevents replay attacks where a captured response is submitted a second time.
 *
 * <p>The {@code rpId} field scopes the session to a specific Relying Party, enabling
 * multi-RP support. A challenge issued by RP-A cannot be consumed by RP-B.
 */
public class ChallengeSession {

    private final String sessionId;
    private final byte[] challengeBytes;
    private final String username;
    /** Relying Party ID this challenge was issued for. */
    private final String rpId;
    private final Instant expiresAt;

    public ChallengeSession(String sessionId,
                            byte[] challengeBytes,
                            String username,
                            String rpId,
                            Instant expiresAt) {
        this.sessionId      = Objects.requireNonNull(sessionId,      "sessionId must not be null");
        this.challengeBytes = Objects.requireNonNull(challengeBytes, "challengeBytes must not be null").clone();
        this.username       = Objects.requireNonNull(username,       "username must not be null");
        this.rpId           = Objects.requireNonNull(rpId,           "rpId must not be null");
        this.expiresAt      = Objects.requireNonNull(expiresAt,      "expiresAt must not be null");
    }

    public String    getSessionId()      { return sessionId; }
    public byte[]    getChallengeBytes() { return challengeBytes.clone(); }
    public String    getUsername()       { return username; }
    public String    getRpId()           { return rpId; }
    public Instant   getExpiresAt()      { return expiresAt; }

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ChallengeSession)) return false;
        return Objects.equals(sessionId, ((ChallengeSession) o).sessionId);
    }

    @Override
    public int hashCode() { return Objects.hash(sessionId); }

    @Override
    public String toString() {
        return "ChallengeSession{sessionId='" + sessionId + "', rpId='" + rpId +
               "', username='" + username + "', expiresAt=" + expiresAt + "}";
    }
}
