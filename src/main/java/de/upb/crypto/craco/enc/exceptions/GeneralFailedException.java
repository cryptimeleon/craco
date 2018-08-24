package de.upb.crypto.craco.enc.exceptions;

/**
 * A general exception that indicates that there was an exception during the
 * runtime processing of the encryption or decryption. This is often caused by
 * invalid keys or internal errors such as bad nonces.
 *
 * @author Mirko Jürgens
 */
abstract class GeneralFailedException extends RuntimeException {

    private static final long serialVersionUID = -1091411052821269358L;

    Exception internalError;

    String cause;

    public GeneralFailedException(Exception e, String cause) {
        super(cause, e);
        internalError = e;
        this.cause = cause;
    }

    public GeneralFailedException(String cause2) {
        super(cause2);
        this.cause = cause2;

    }


}
