package com.example.fido2.application.port.out;

import com.example.fido2.domain.model.User;

import java.util.Optional;

/**
 * Driven port (output) — persistence contract for {@link User} entities.
 */
public interface UserRepository {

    /** Looks up a user by their username (e.g. email address). */
    Optional<User> findByUsername(String username);

    /**
     * Returns the existing user for {@code username} or creates and persists a new one.
     * Safe to call concurrently — implementations must guarantee exactly-once creation.
     */
    User findOrCreate(String username, String displayName);
}
