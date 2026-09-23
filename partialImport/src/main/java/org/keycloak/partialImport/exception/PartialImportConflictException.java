package org.keycloak.partialImport.exception;

public class PartialImportConflictException extends RuntimeException {

    public PartialImportConflictException(String message) {
        super(message);
    }
}