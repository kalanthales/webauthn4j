package com.webauthn4j.verifier.exception;

import org.jetbrains.annotations.Nullable;

public class CertificateChainVerificationException extends VerificationException{

    public CertificateChainVerificationException(@Nullable String message, @Nullable Throwable cause) {
        super(message, cause);
    }

    public CertificateChainVerificationException(@Nullable String message) {
        super(message);
    }

    public CertificateChainVerificationException(@Nullable Throwable cause) {
        super(cause);
    }
}
