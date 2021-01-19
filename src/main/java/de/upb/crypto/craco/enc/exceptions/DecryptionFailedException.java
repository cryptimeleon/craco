package de.upb.crypto.craco.enc.exceptions;

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * Exception thrown when decryption fails.
 */
public class DecryptionFailedException extends GeneralFailedException {

    private static final long serialVersionUID = 7554495395019283872L;

    public DecryptionFailedException(String cause, GeneralSecurityException e) {
        super(e, cause);
    }

    public DecryptionFailedException(IOException e, String localizedMessage) {
        super(e, localizedMessage);
    }
}
