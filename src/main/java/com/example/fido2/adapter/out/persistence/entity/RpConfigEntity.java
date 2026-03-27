package com.example.fido2.adapter.out.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/**
 * JPA entity mapping to the {@code rp_config} table.
 *
 * <p>Each row represents a registered Relying Party with its own WebAuthn settings
 * and Basic Auth password for API access control.
 */
@Entity
@Table(name = "rp_config")
public class RpConfigEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "rp_id", nullable = false, unique = true, length = 256)
    private String rpId;

    @Column(name = "rp_name", nullable = false, length = 256)
    private String rpName;

    @Column(name = "origin", nullable = false, length = 2048)
    private String origin;

    @Column(name = "challenge_ttl_seconds", nullable = false)
    private long challengeTtlSeconds;

    @Column(name = "rp_password", nullable = false, length = 256)
    private String rpPassword;

    @Column(name = "active", nullable = false)
    private boolean active;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected RpConfigEntity() {}

    public Long    getId()                   { return id; }
    public String  getRpId()                 { return rpId; }
    public String  getRpName()               { return rpName; }
    public String  getOrigin()               { return origin; }
    public long    getChallengeTtlSeconds()  { return challengeTtlSeconds; }
    public String  getRpPassword()           { return rpPassword; }
    public boolean isActive()                { return active; }
    public Instant getCreatedAt()            { return createdAt; }
    public Instant getUpdatedAt()            { return updatedAt; }
}
