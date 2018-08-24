package de.upb.crypto.craco.enc.streaming.test;

import de.upb.crypto.craco.interfaces.KeyPair;
import de.upb.crypto.craco.interfaces.StreamingEncryptionScheme;

public class StreamingEncryptionSchemeParams {

    private StreamingEncryptionScheme encryptionScheme;

    private KeyPair keyPair;

    public StreamingEncryptionSchemeParams(StreamingEncryptionScheme encryptionScheme, KeyPair keyPair) {
        this.encryptionScheme = encryptionScheme;
        this.keyPair = keyPair;
    }

    public StreamingEncryptionScheme getEncryptionScheme() {
        return encryptionScheme;
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public String toString() {
        return encryptionScheme.getClass().getName();
    }
}
