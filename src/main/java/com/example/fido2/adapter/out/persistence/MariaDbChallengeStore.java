package com.example.fido2.adapter.out.persistence;

import com.example.fido2.adapter.out.persistence.entity.ChallengeSessionEntity;
import com.example.fido2.adapter.out.persistence.repository.ChallengeSessionJpaRepository;
import com.example.fido2.application.port.out.ChallengeStore;
import com.example.fido2.domain.model.ChallengeSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

@Repository
public class MariaDbChallengeStore implements ChallengeStore {

    private static final Logger log = LoggerFactory.getLogger(MariaDbChallengeStore.class);

    private final ChallengeSessionJpaRepository jpa;

    public MariaDbChallengeStore(ChallengeSessionJpaRepository jpa) {
        this.jpa = jpa;
    }

    @Override
    @Transactional
    public void store(ChallengeSession session) {
        String challengeB64 = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(session.getChallengeBytes());

        jpa.save(new ChallengeSessionEntity(
                session.getSessionId(), challengeB64,
                session.getUsername(), session.getRpId(),
                session.getExpiresAt(), Instant.now()
        ));
        log.debug("Stored challenge session: sessionId='{}', rpId='{}', username='{}'",
                session.getSessionId(), session.getRpId(), session.getUsername());
    }

    @Override
    @Transactional
    public Optional<ChallengeSession> findAndRemove(String sessionId) {
        Optional<ChallengeSessionEntity> found = jpa.findByIdForUpdate(sessionId);
        if (found.isEmpty()) {
            log.debug("Challenge session not found or already consumed: '{}'", sessionId);
            return Optional.empty();
        }
        ChallengeSessionEntity entity = found.get();
        jpa.delete(entity);
        jpa.flush();
        log.debug("Consumed challenge session: sessionId='{}', rpId='{}'",
                sessionId, entity.getRpId());
        return Optional.of(toDomain(entity));
    }

    @Scheduled(fixedDelay = 60_000)
    @Transactional
    public void evictExpiredSessions() {
        int deleted = jpa.deleteExpiredSessions(Instant.now());
        if (deleted > 0) {
            log.debug("Evicted {} expired challenge session(s)", deleted);
        }
    }

    private ChallengeSession toDomain(ChallengeSessionEntity e) {
        byte[] challengeBytes = Base64.getUrlDecoder().decode(e.getChallengeBytes());
        return new ChallengeSession(
                e.getSessionId(), challengeBytes, e.getUsername(), e.getRpId(), e.getExpiresAt());
    }
}
