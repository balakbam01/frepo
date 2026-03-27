package com.example.fido2.domain.model;

import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;

/**
 * Value object representing a WebAuthn user handle (user.id).
 *
 * <p>The user handle is an opaque byte array assigned to a user at registration time.
 * Per the WebAuthn spec it MUST NOT contain personally identifiable information
 * (use a random UUID, not the username or email).
 */
public final class UserId {

    private final byte[] value;

    public UserId(byte[] value) {
        Objects.requireNonNull(value, "UserId value must not be null");
        this.value = Arrays.copyOf(value, value.length);
    }

    /** Factory: creates a fresh random 16-byte user handle. */
    public static UserId random() {
        UUID uuid = UUID.randomUUID();
        byte[] bytes = new byte[16];
        long msb = uuid.getMostSignificantBits();
        long lsb = uuid.getLeastSignificantBits();
        for (int i = 0; i < 8; i++) {
            bytes[i]     = (byte) (msb >>> (56 - 8 * i));
            bytes[i + 8] = (byte) (lsb >>> (56 - 8 * i));
        }
        return new UserId(bytes);
    }

    public byte[] getValue() {
        return Arrays.copyOf(value, value.length);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof UserId)) return false;
        return Arrays.equals(value, ((UserId) o).value);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(value);
    }

    @Override
    public String toString() {
        return "UserId[" + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(value) + "]";
    }
}
