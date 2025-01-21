package com.webauthn4j.verifier.exception;

import org.jetbrains.annotations.Nullable;

public class RootCertificateNotVerifiedException extends VerificationException{
    public RootCertificateNotVerifiedException(@Nullable String message, @Nullable Throwable cause) {
        super(message, cause);
    }

    public RootCertificateNotVerifiedException(@Nullable String message) {
        super(message);
    }

    public RootCertificateNotVerifiedException(@Nullable Throwable cause) {
        super(cause);
    }
}
