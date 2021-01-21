package de.upb.crypto.craco.enc.exceptions;

public class IllegalKeyException extends GeneralFailedException {

    private static final long serialVersionUID = 1L;

    public IllegalKeyException(String cause) {
        super(cause);
    }
}
