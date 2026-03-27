package com.example.fido2.adapter.out.persistence;

import com.example.fido2.adapter.out.persistence.entity.UserEntity;
import com.example.fido2.adapter.out.persistence.repository.UserJpaRepository;
import com.example.fido2.application.port.out.UserRepository;
import com.example.fido2.domain.model.User;
import com.example.fido2.domain.model.UserId;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

/**
 * MariaDB-backed implementation of {@link UserRepository}.
 *
 * <p>{@link #findOrCreate(String, String)} uses Spring's {@code @Transactional} with
 * a read-then-write pattern. Because MariaDB's default isolation is REPEATABLE_READ
 * and inserts use a unique key constraint on {@code username}, a concurrent duplicate
 * insert will receive a constraint violation which is re-mapped to a read of the
 * already-existing row.
 */
@Repository
public class MariaDbUserRepository implements UserRepository {

    private static final Logger log = LoggerFactory.getLogger(MariaDbUserRepository.class);

    private final UserJpaRepository jpa;

    public MariaDbUserRepository(UserJpaRepository jpa) {
        this.jpa = jpa;
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<User> findByUsername(String username) {
        log.debug("findByUsername: '{}'", username);
        return jpa.findByUsername(normalise(username)).map(this::toDomain);
    }

    @Override
    @Transactional
    public User findOrCreate(String username, String displayName) {
        String key = normalise(username);
        Optional<UserEntity> existing = jpa.findByUsername(key);
        if (existing.isPresent()) {
            log.debug("findOrCreate: existing user found for '{}'", username);
            return toDomain(existing.get());
        }

        UserId userId = UserId.random();
        String userIdB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(userId.getValue());
        UserEntity entity = new UserEntity(userIdB64, key, displayName, Instant.now());
        jpa.save(entity);
        log.info("Created new user in DB: username='{}', userId='{}'", key, userIdB64);
        return toDomain(entity);
    }

    // ── Mapping ───────────────────────────────────────────────────────────

    private User toDomain(UserEntity e) {
        byte[] userIdBytes = Base64.getUrlDecoder().decode(e.getUserId());
        return new User(new UserId(userIdBytes), e.getUsername(), e.getDisplayName(), e.getCreatedAt());
    }

    private String normalise(String username) {
        return username.trim().toLowerCase();
    }
}
