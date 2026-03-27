package com.example.fido2.domain.model;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Domain value object representing a FIDO2 Relying Party configuration.
 *
 * <p>Each RP has its own identity ({@code rpId}, {@code origin}), name, challenge TTL,
 * and a password used for Basic Auth access control on the API layer.
 *
 * <p>Loaded from the {@code rp_config} database table on every request. Instances are
 * attached to the current HTTP request as an attribute by {@code FidoBasicAuthFilter}.
 */
public class RpConfig {

    private final String rpId;
    private final String rpName;
    private final String origin;
    private final long challengeTtlSeconds;

    /**
     * Password used in the {@code Authorization: Basic base64(rpId:rpPassword)} header.
     * <p><strong>Production note:</strong> store a BCrypt hash and verify with
     * {@code BCryptPasswordEncoder} rather than plain-text comparison.
     */
    private final String rpPassword;

    private final boolean active;
    private final Instant createdAt;
    private final Instant updatedAt;

    public RpConfig(String rpId, String rpName, String origin,
                    long challengeTtlSeconds, String rpPassword,
                    boolean active, Instant createdAt, Instant updatedAt) {
        this.rpId                 = Objects.requireNonNull(rpId);
        this.rpName               = Objects.requireNonNull(rpName);
        this.origin               = Objects.requireNonNull(origin);
        this.challengeTtlSeconds  = challengeTtlSeconds;
        this.rpPassword           = Objects.requireNonNull(rpPassword);
        this.active               = active;
        this.createdAt            = createdAt;
        this.updatedAt            = updatedAt;
    }

    public String getRpId()               { return rpId; }
    public String getRpName()             { return rpName; }
    /** Raw comma-separated origin string as stored in the database. */
    public String getOrigin()             { return origin; }
    /**
     * Returns the set of allowed origins parsed from the comma-separated {@code origin} field.
     * Each entry is trimmed; blank entries are discarded.
     */
    public Set<String> getOrigins() {
        return Arrays.stream(origin.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toSet());
    }
    public long getChallengeTtlSeconds()  { return challengeTtlSeconds; }
    public String getRpPassword()         { return rpPassword; }
    public boolean isActive()             { return active; }
    public Instant getCreatedAt()         { return createdAt; }
    public Instant getUpdatedAt()         { return updatedAt; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof RpConfig)) return false;
        return Objects.equals(rpId, ((RpConfig) o).rpId);
    }

    @Override
    public int hashCode() { return Objects.hash(rpId); }

    @Override
    public String toString() {
        return "RpConfig{rpId='" + rpId + "', origin='" + origin + "', active=" + active + "}";
    }
}
