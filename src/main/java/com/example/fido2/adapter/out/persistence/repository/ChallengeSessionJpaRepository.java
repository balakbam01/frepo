package com.example.fido2.adapter.out.persistence.repository;

import com.example.fido2.adapter.out.persistence.entity.ChallengeSessionEntity;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;

/** Spring Data JPA repository for {@link ChallengeSessionEntity}. */
public interface ChallengeSessionJpaRepository extends JpaRepository<ChallengeSessionEntity, String> {

    /**
     * Acquires a pessimistic write lock (SELECT ... FOR UPDATE) on the session row.
     *
     * <p>Used by {@code MariaDbChallengeStore.findAndRemove()} to guarantee that two
     * concurrent requests for the same sessionId cannot both succeed — only the first
     * transaction to commit the subsequent DELETE will "win". The second transaction
     * will find no row and return empty.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT c FROM ChallengeSessionEntity c WHERE c.sessionId = :sessionId")
    Optional<ChallengeSessionEntity> findByIdForUpdate(@Param("sessionId") String sessionId);

    /**
     * Bulk-deletes all sessions whose TTL has elapsed.
     * Called by the scheduled cleanup task.
     */
    @Modifying
    @Query("DELETE FROM ChallengeSessionEntity c WHERE c.expiresAt < :now")
    int deleteExpiredSessions(@Param("now") Instant now);
}
