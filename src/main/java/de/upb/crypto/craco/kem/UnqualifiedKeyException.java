package de.upb.crypto.craco.kem;

/**
 * Exception to signal that a given secret key is not qualified to decrypt a given ciphertext.
 *
 * @author peter.guenther
 */
public class UnqualifiedKeyException extends RuntimeException {
    private static final long serialVersionUID = 1L;


    public UnqualifiedKeyException() {
        super();
    }

    public UnqualifiedKeyException(String e) {
        super(e);
    }
}
