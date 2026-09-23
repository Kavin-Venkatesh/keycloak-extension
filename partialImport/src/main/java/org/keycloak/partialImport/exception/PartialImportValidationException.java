package org.keycloak.partialImport.exception;

public class PartialImportValidationException extends RuntimeException {

    public PartialImportValidationException(String message) {
        super(message);
    }

    public PartialImportValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
