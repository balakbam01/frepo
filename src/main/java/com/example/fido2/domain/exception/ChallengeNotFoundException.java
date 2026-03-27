package com.example.fido2.domain.exception;

public class ChallengeNotFoundException extends RuntimeException {

    public ChallengeNotFoundException(String message) {
        super(message);
    }

    public ChallengeNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
