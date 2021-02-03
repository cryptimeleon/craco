package de.upb.crypto.craco.enc.representation;

import de.upb.crypto.craco.common.plaintexts.PlainText;
import de.upb.crypto.craco.enc.CipherText;
import de.upb.crypto.craco.enc.DecryptionKey;
import de.upb.crypto.craco.enc.EncryptionKey;
import de.upb.crypto.craco.enc.EncryptionScheme;

public class RepresentationTestParams {
    protected EncryptionScheme scheme;
    protected EncryptionKey encryptionKey;
    protected DecryptionKey decryptionKey;
    protected PlainText plainText;
    protected CipherText cipherText;

    public RepresentationTestParams(EncryptionScheme scheme, EncryptionKey encryptionKey, DecryptionKey decryptionKey,
                                    PlainText plainText, CipherText cipherText) {
        super();
        this.scheme = scheme;
        this.encryptionKey = encryptionKey;
        this.decryptionKey = decryptionKey;
        this.plainText = plainText;
        this.cipherText = cipherText;
    }


    public String toString() {
        return scheme.getClass().getName();
    }
}
