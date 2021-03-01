package org.cryptimeleon.craco.enc;

import org.cryptimeleon.craco.common.plaintexts.PlainText;

import java.util.function.Supplier;

public class TestParams {

    protected EncryptionScheme encryptionScheme;

    protected Supplier<PlainText> plainTextSupplier;

    protected EncryptionKeyPair validKeyPair;

    protected EncryptionKeyPair invalidKeyPair;

    /**
     * Test parameters
     *
     * @param largeScheme        the encryption scheme to test
     * @param abeCPLargeSupplier a supplier for (possibly random) plaintexts to encrypt and decrypt
     */
    public TestParams(EncryptionScheme largeScheme, Supplier<PlainText> abeCPLargeSupplier, EncryptionKeyPair validKeyPair,
                      EncryptionKeyPair invalidKeyPair) {
        this.encryptionScheme = largeScheme;
        this.plainTextSupplier = abeCPLargeSupplier;
        this.validKeyPair = validKeyPair;
        this.invalidKeyPair = invalidKeyPair;
    }

    public String toString() {
        return encryptionScheme.getClass().getName();
    }

}
