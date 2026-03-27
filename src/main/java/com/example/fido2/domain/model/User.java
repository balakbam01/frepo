package com.example.fido2.domain.model;

import java.time.Instant;
import java.util.Objects;

/**
 * Domain entity representing a registered user.
 *
 * <p>The {@link UserId} is the WebAuthn user handle — an opaque, non-PII byte array.
 * The {@code username} is the human-readable account identifier (e.g. email address).
 */
public class User {

    private final UserId userId;
    private final String username;
    private final String displayName;
    private final Instant createdAt;

    public User(UserId userId, String username, String displayName, Instant createdAt) {
        this.userId      = Objects.requireNonNull(userId, "userId must not be null");
        this.username    = Objects.requireNonNull(username, "username must not be null");
        this.displayName = displayName != null ? displayName : username;
        this.createdAt   = Objects.requireNonNull(createdAt, "createdAt must not be null");
    }

    public UserId getUserId() {
        return userId;
    }

    public String getUsername() {
        return username;
    }

    public String getDisplayName() {
        return displayName;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof User)) return false;
        return Objects.equals(userId, ((User) o).userId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(userId);
    }

    @Override
    public String toString() {
        return "User{username='" + username + "', userId=" + userId + "}";
    }
}
