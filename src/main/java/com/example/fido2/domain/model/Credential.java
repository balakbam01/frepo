package com.example.fido2.domain.model;

import java.time.Instant;
import java.util.Collections;
import java.util.Objects;
import java.util.Set;

/**
 * Domain aggregate root representing a stored WebAuthn credential.
 *
 * <p>The {@code rpId} field scopes this credential to a specific Relying Party, allowing
 * the same user to hold independent credentials for multiple RPs.
 *
 * <p>The {@code attestedCredentialDataBytes} field stores the CBOR-serialised
 * {@code AttestedCredentialData} produced by {@code AttestedCredentialDataConverter}.
 * Serialising to raw bytes avoids holding non-serialisable WebAuthn4J objects in the
 * domain layer while keeping the public key fully recoverable for authentication.
 *
 * <p>The {@code signCount} is mutable — it MUST be updated after every successful
 * authentication to detect authenticator cloning (RFC 8471 §6.1).
 */
public class Credential {

    private final CredentialId credentialId;
    private final UserId userId;
    private final String username;
    /** Relying Party ID this credential was registered with. */
    private final String rpId;
    private final byte[] attestedCredentialDataBytes;
    private long signCount;
    private final Set<String> transports;
    private final Instant registeredAt;
    private Instant lastUsedAt;

    private Credential(Builder builder) {
        this.credentialId              = Objects.requireNonNull(builder.credentialId);
        this.userId                    = Objects.requireNonNull(builder.userId);
        this.username                  = Objects.requireNonNull(builder.username);
        this.rpId                      = Objects.requireNonNull(builder.rpId);
        this.attestedCredentialDataBytes = Objects.requireNonNull(builder.attestedCredentialDataBytes);
        this.signCount                 = builder.signCount;
        this.transports                = builder.transports != null
                ? Collections.unmodifiableSet(builder.transports) : Collections.emptySet();
        this.registeredAt              = builder.registeredAt != null ? builder.registeredAt : Instant.now();
        this.lastUsedAt                = builder.lastUsedAt;
    }

    public CredentialId getCredentialId()            { return credentialId; }
    public UserId       getUserId()                  { return userId; }
    public String       getUsername()                { return username; }
    public String       getRpId()                    { return rpId; }
    public byte[]       getAttestedCredentialDataBytes() { return attestedCredentialDataBytes.clone(); }
    public long         getSignCount()               { return signCount; }
    public Set<String>  getTransports()              { return transports; }
    public Instant      getRegisteredAt()            { return registeredAt; }
    public Instant      getLastUsedAt()              { return lastUsedAt; }

    public void updateAfterAuthentication(long newSignCount) {
        this.signCount  = newSignCount;
        this.lastUsedAt = Instant.now();
    }

    public static Builder builder() { return new Builder(); }

    public static final class Builder {
        private CredentialId credentialId;
        private UserId       userId;
        private String       username;
        private String       rpId;
        private byte[]       attestedCredentialDataBytes;
        private long         signCount;
        private Set<String>  transports;
        private Instant      registeredAt;
        private Instant      lastUsedAt;

        public Builder credentialId(CredentialId v)             { this.credentialId = v; return this; }
        public Builder userId(UserId v)                          { this.userId = v; return this; }
        public Builder username(String v)                        { this.username = v; return this; }
        public Builder rpId(String v)                            { this.rpId = v; return this; }
        public Builder attestedCredentialDataBytes(byte[] v)    { this.attestedCredentialDataBytes = v; return this; }
        public Builder signCount(long v)                         { this.signCount = v; return this; }
        public Builder transports(Set<String> v)                 { this.transports = v; return this; }
        public Builder registeredAt(Instant v)                   { this.registeredAt = v; return this; }
        public Builder lastUsedAt(Instant v)                     { this.lastUsedAt = v; return this; }
        public Credential build()                                { return new Credential(this); }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Credential)) return false;
        return Objects.equals(credentialId, ((Credential) o).credentialId);
    }

    @Override
    public int hashCode() { return Objects.hash(credentialId); }

    @Override
    public String toString() {
        return "Credential{id=" + credentialId + ", rpId='" + rpId +
               "', username='" + username + "', signCount=" + signCount + "}";
    }
}
