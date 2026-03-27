package com.example.fido2.adapter.out.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/**
 * JPA entity mapping to the {@code users} table.
 *
 * <p>{@code userId} stores the base64url-encoded WebAuthn user handle.
 * It is separate from {@code id} (surrogate PK) and is exposed to WebAuthn clients.
 */
@Entity
@Table(name = "users")
public class UserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** Base64url-encoded 16-byte WebAuthn user handle. */
    @Column(name = "user_id", nullable = false, unique = true, length = 24)
    private String userId;

    @Column(name = "username", nullable = false, unique = true, length = 256)
    private String username;

    @Column(name = "display_name", nullable = false, length = 256)
    private String displayName;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    protected UserEntity() {}

    public UserEntity(String userId, String username, String displayName, Instant createdAt) {
        this.userId      = userId;
        this.username    = username;
        this.displayName = displayName;
        this.createdAt   = createdAt;
    }

    public Long getId()           { return id; }
    public String getUserId()     { return userId; }
    public String getUsername()   { return username; }
    public String getDisplayName(){ return displayName; }
    public Instant getCreatedAt() { return createdAt; }
}
