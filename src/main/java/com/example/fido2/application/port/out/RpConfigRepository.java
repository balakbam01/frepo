package com.example.fido2.application.port.out;

import com.example.fido2.domain.model.RpConfig;

import java.util.Optional;

/**
 * Driven port (output) — persistence contract for {@link RpConfig} entities.
 *
 * <p>Used by {@code FidoBasicAuthFilter} on every inbound API request to resolve
 * and authenticate the Relying Party from the {@code Authorization} header.
 */
public interface RpConfigRepository {

    /**
     * Looks up an active RP configuration by {@code rpId}.
     * Returns empty if the RP does not exist or is inactive.
     */
    Optional<RpConfig> findActiveByRpId(String rpId);
}
