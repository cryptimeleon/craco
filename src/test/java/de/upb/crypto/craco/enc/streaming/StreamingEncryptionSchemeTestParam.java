package de.upb.crypto.craco.enc.streaming;

import de.upb.crypto.craco.common.interfaces.KeyPair;
import de.upb.crypto.craco.common.interfaces.StreamingEncryptionScheme;

/**
 * Parameters for use with {@link StreamingEncryptionSchemeTester}.
 */
public class StreamingEncryptionSchemeTestParam {

    /**
     * The class of the scheme.
     */
    protected Class<? extends StreamingEncryptionScheme> clazz;

    /**
     * The scheme these parameters are for.
     */
    protected StreamingEncryptionScheme scheme;

    /**
     * The valid keypair to use in the tests.
     */
    protected KeyPair keyPair;

    public StreamingEncryptionSchemeTestParam(StreamingEncryptionScheme encryptionScheme, KeyPair keyPair) {
        this.scheme = encryptionScheme;
        this.clazz = encryptionScheme.getClass();
        this.keyPair = keyPair;
    }

    public StreamingEncryptionSchemeTestParam(Class<? extends StreamingEncryptionScheme> clazz) {
        this.clazz = clazz;
    }

    public Class<? extends StreamingEncryptionScheme> getClazz() {
        return clazz;
    }

    public StreamingEncryptionScheme getScheme() {
        return scheme;
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public String toString() {
        return scheme.getClass().getName();
    }
}
