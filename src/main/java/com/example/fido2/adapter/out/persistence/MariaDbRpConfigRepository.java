package com.example.fido2.adapter.out.persistence;

import com.example.fido2.adapter.out.persistence.entity.RpConfigEntity;
import com.example.fido2.adapter.out.persistence.repository.RpConfigJpaRepository;
import com.example.fido2.application.port.out.RpConfigRepository;
import com.example.fido2.domain.model.RpConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

/**
 * MariaDB-backed implementation of {@link RpConfigRepository}.
 *
 * <p>Called on every inbound API request by {@code FidoBasicAuthFilter}, so this method
 * must be fast. In production, wrap with a short-lived cache (e.g. Caffeine) to avoid
 * a DB round-trip per request while still picking up RP config changes within seconds.
 */
@Repository
public class MariaDbRpConfigRepository implements RpConfigRepository {

    private static final Logger log = LoggerFactory.getLogger(MariaDbRpConfigRepository.class);

    private final RpConfigJpaRepository jpa;

    public MariaDbRpConfigRepository(RpConfigJpaRepository jpa) {
        this.jpa = jpa;
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<RpConfig> findActiveByRpId(String rpId) {
        log.debug("Loading RP config for rpId='{}'", rpId);
        return jpa.findByRpIdAndActiveTrue(rpId).map(this::toDomain);
    }

    private RpConfig toDomain(RpConfigEntity e) {
        return new RpConfig(
                e.getRpId(), e.getRpName(), e.getOrigin(),
                e.getChallengeTtlSeconds(), e.getRpPassword(),
                e.isActive(), e.getCreatedAt(), e.getUpdatedAt()
        );
    }
}
