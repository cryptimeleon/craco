package org.cryptimeleon.craco.enc.representation;

import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.enc.CipherText;
import org.cryptimeleon.craco.enc.DecryptionKey;
import org.cryptimeleon.craco.enc.EncryptionKey;
import org.cryptimeleon.craco.enc.EncryptionScheme;

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
