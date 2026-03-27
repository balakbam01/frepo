package com.example.fido2.adapter.out.persistence.repository;

import com.example.fido2.adapter.out.persistence.entity.CredentialEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface CredentialJpaRepository extends JpaRepository<CredentialEntity, Long> {

    /** Find credential scoped to a specific RP. */
    Optional<CredentialEntity> findByCredentialIdAndRpId(String credentialId, String rpId);

    /** All credentials a user has registered with a specific RP. */
    List<CredentialEntity> findByUserIdAndRpId(String userId, String rpId);

    /** Atomic sign-count + last-used update, scoped to the RP. */
    @Modifying
    @Query("UPDATE CredentialEntity c " +
           "SET c.signCount = :signCount, c.lastUsedAt = :lastUsedAt " +
           "WHERE c.credentialId = :credentialId AND c.rpId = :rpId")
    int updateSignCount(@Param("credentialId") String credentialId,
                        @Param("rpId")         String rpId,
                        @Param("signCount")    long   signCount,
                        @Param("lastUsedAt")   Instant lastUsedAt);
}
