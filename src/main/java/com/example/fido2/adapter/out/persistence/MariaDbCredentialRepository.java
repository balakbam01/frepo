package com.example.fido2.adapter.out.persistence;

import com.example.fido2.adapter.out.persistence.entity.CredentialEntity;
import com.example.fido2.adapter.out.persistence.repository.CredentialJpaRepository;
import com.example.fido2.application.port.out.CredentialRepository;
import com.example.fido2.domain.model.Credential;
import com.example.fido2.domain.model.CredentialId;
import com.example.fido2.domain.model.UserId;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Repository
public class MariaDbCredentialRepository implements CredentialRepository {

    private static final Logger log = LoggerFactory.getLogger(MariaDbCredentialRepository.class);

    private final CredentialJpaRepository jpa;

    public MariaDbCredentialRepository(CredentialJpaRepository jpa) {
        this.jpa = jpa;
    }

    @Override
    @Transactional
    public void save(Credential credential) {
        String credIdB64 = credential.getCredentialId().toBase64Url();
        String userIdB64 = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(credential.getUserId().getValue());

        CredentialEntity entity = new CredentialEntity(
                credIdB64, userIdB64, credential.getUsername(), credential.getRpId(),
                credential.getAttestedCredentialDataBytes(), credential.getSignCount(),
                credential.getTransports(),
                credential.getRegisteredAt() != null ? credential.getRegisteredAt() : Instant.now()
        );
        jpa.save(entity);
        log.debug("Saved credential: credentialId='{}', rpId='{}'", credIdB64, credential.getRpId());
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<Credential> findByCredentialId(CredentialId credentialId, String rpId) {
        String key = credentialId.toBase64Url();
        log.debug("findByCredentialId: '{}', rpId='{}'", key, rpId);
        return jpa.findByCredentialIdAndRpId(key, rpId).map(this::toDomain);
    }

    @Override
    @Transactional(readOnly = true)
    public List<Credential> findByUserId(UserId userId, String rpId) {
        String userIdB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(userId.getValue());
        log.debug("findByUserId: '{}', rpId='{}'", userIdB64, rpId);
        return jpa.findByUserIdAndRpId(userIdB64, rpId).stream()
                .map(this::toDomain).collect(Collectors.toList());
    }

    @Override
    @Transactional
    public void updateSignCount(CredentialId credentialId, String rpId, long newSignCount) {
        String key     = credentialId.toBase64Url();
        int    updated = jpa.updateSignCount(key, rpId, newSignCount, Instant.now());
        if (updated == 0) {
            log.warn("updateSignCount: no row found for credentialId='{}', rpId='{}'", key, rpId);
        } else {
            log.debug("updateSignCount: credentialId='{}', rpId='{}', newCount={}", key, rpId, newSignCount);
        }
    }

    private Credential toDomain(CredentialEntity e) {
        byte[] credIdBytes = Base64.getUrlDecoder().decode(e.getCredentialId());
        byte[] userIdBytes = Base64.getUrlDecoder().decode(e.getUserId());
        return Credential.builder()
                .credentialId(new CredentialId(credIdBytes))
                .userId(new UserId(userIdBytes))
                .username(e.getUsername())
                .rpId(e.getRpId())
                .attestedCredentialDataBytes(e.getAttestedCredentialData())
                .signCount(e.getSignCount())
                .transports(e.getTransports())
                .registeredAt(e.getRegisteredAt())
                .lastUsedAt(e.getLastUsedAt())
                .build();
    }
}
