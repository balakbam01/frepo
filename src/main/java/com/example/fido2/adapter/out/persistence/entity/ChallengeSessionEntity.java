package com.example.fido2.adapter.out.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "challenge_sessions")
public class ChallengeSessionEntity {

    @Id
    @Column(name = "session_id", length = 36)
    private String sessionId;

    @Column(name = "challenge_bytes", nullable = false, length = 64)
    private String challengeBytes;

    @Column(name = "username", nullable = false, length = 256)
    private String username;

    /** Relying Party this challenge session was issued for. */
    @Column(name = "rp_id", nullable = false, length = 256)
    private String rpId;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    protected ChallengeSessionEntity() {}

    public ChallengeSessionEntity(String sessionId, String challengeBytes,
                                   String username, String rpId,
                                   Instant expiresAt, Instant createdAt) {
        this.sessionId      = sessionId;
        this.challengeBytes = challengeBytes;
        this.username       = username;
        this.rpId           = rpId;
        this.expiresAt      = expiresAt;
        this.createdAt      = createdAt;
    }

    public String  getSessionId()      { return sessionId; }
    public String  getChallengeBytes() { return challengeBytes; }
    public String  getUsername()       { return username; }
    public String  getRpId()           { return rpId; }
    public Instant getExpiresAt()      { return expiresAt; }
    public Instant getCreatedAt()      { return createdAt; }
}
