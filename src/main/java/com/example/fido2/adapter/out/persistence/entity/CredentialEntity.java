package com.example.fido2.adapter.out.persistence.entity;

import com.example.fido2.adapter.out.persistence.converter.StringSetConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "credentials")
public class CredentialEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "credential_id", nullable = false, unique = true, length = 512)
    private String credentialId;

    @Column(name = "user_id", nullable = false, length = 24)
    private String userId;

    @Column(name = "username", nullable = false, length = 256)
    private String username;

    /** Relying Party this credential was registered with. */
    @Column(name = "rp_id", nullable = false, length = 256)
    private String rpId;

    @Column(name = "attested_credential_data", nullable = false, columnDefinition = "LONGBLOB")
    private byte[] attestedCredentialData;

    @Column(name = "sign_count", nullable = false)
    private long signCount;

    @Convert(converter = StringSetConverter.class)
    @Column(name = "transports", length = 256)
    private Set<String> transports = new HashSet<>();

    @Column(name = "registered_at", nullable = false, updatable = false)
    private Instant registeredAt;

    @Column(name = "last_used_at")
    private Instant lastUsedAt;

    protected CredentialEntity() {}

    public CredentialEntity(String credentialId, String userId, String username, String rpId,
                             byte[] attestedCredentialData, long signCount, Set<String> transports,
                             Instant registeredAt) {
        this.credentialId           = credentialId;
        this.userId                 = userId;
        this.username               = username;
        this.rpId                   = rpId;
        this.attestedCredentialData = attestedCredentialData;
        this.signCount              = signCount;
        this.transports             = transports != null ? new HashSet<>(transports) : new HashSet<>();
        this.registeredAt           = registeredAt;
    }

    public Long      getId()                       { return id; }
    public String    getCredentialId()             { return credentialId; }
    public String    getUserId()                   { return userId; }
    public String    getUsername()                 { return username; }
    public String    getRpId()                     { return rpId; }
    public byte[]    getAttestedCredentialData()   { return attestedCredentialData; }
    public long      getSignCount()                { return signCount; }
    public Set<String> getTransports()             { return transports; }
    public Instant   getRegisteredAt()             { return registeredAt; }
    public Instant   getLastUsedAt()               { return lastUsedAt; }

    public void setSignCount(long signCount)        { this.signCount = signCount; }
    public void setLastUsedAt(Instant lastUsedAt)   { this.lastUsedAt = lastUsedAt; }
}
