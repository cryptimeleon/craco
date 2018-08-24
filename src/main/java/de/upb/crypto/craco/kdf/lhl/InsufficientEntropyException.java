package de.upb.crypto.craco.kdf.lhl;

public class InsufficientEntropyException extends Exception {

    /**
     *
     */
    private static final long serialVersionUID = -3931764095188970356L;


    public InsufficientEntropyException(String message) {
        super(message);
    }
}
