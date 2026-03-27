package com.example.fido2.adapter.out.persistence.converter;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * JPA {@link AttributeConverter} that maps a {@code Set<String>} to a comma-separated
 * VARCHAR column and back.
 *
 * <p>Example: {@code {"internal", "usb"}} ↔ {@code "internal,usb"}
 *
 * <p>{@code autoApply = false} — apply explicitly via {@code @Convert} on each field
 * to avoid unintended coercions.
 */
@Converter(autoApply = false)
public class StringSetConverter implements AttributeConverter<Set<String>, String> {

    private static final String DELIMITER = ",";

    @Override
    public String convertToDatabaseColumn(Set<String> set) {
        if (set == null || set.isEmpty()) {
            return null;
        }
        return String.join(DELIMITER, set);
    }

    @Override
    public Set<String> convertToEntityAttribute(String value) {
        if (value == null || value.isBlank()) {
            return new HashSet<>();
        }
        return new HashSet<>(Arrays.asList(value.split(DELIMITER)));
    }
}
