package org.cryptimeleon.craco.enc.streaming;

import org.cryptimeleon.craco.enc.EncryptionKeyPair;
import org.cryptimeleon.craco.enc.StreamingEncryptionScheme;

public class StreamingEncryptionSchemeParams {

    private StreamingEncryptionScheme encryptionScheme;

    private EncryptionKeyPair keyPair;

    public StreamingEncryptionSchemeParams(StreamingEncryptionScheme encryptionScheme, EncryptionKeyPair keyPair) {
        this.encryptionScheme = encryptionScheme;
        this.keyPair = keyPair;
    }

    public StreamingEncryptionScheme getEncryptionScheme() {
        return encryptionScheme;
    }

    public EncryptionKeyPair getKeyPair() {
        return keyPair;
    }

    public String toString() {
        return encryptionScheme.getClass().getName();
    }
}
