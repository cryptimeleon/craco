package de.upb.crypto.craco.enc.test;

import de.upb.crypto.craco.interfaces.EncryptionScheme;
import de.upb.crypto.craco.interfaces.KeyPair;
import de.upb.crypto.craco.interfaces.PlainText;

import java.util.function.Supplier;

public class TestParams {

    protected EncryptionScheme encryptionScheme;

    protected Supplier<PlainText> plainTextSupplier;

    protected KeyPair validKeyPair;

    protected KeyPair invalidKeyPair;

    /**
     * Test parameters
     *
     * @param largeScheme        the encryption scheme to test
     * @param abeCPLargeSupplier a supplier for (possibly random) plaintexts to encrypt and decrypt
     */
    public TestParams(EncryptionScheme largeScheme, Supplier<PlainText> abeCPLargeSupplier, KeyPair validKeyPair,
                      KeyPair invalidKeyPair) {
        this.encryptionScheme = largeScheme;
        this.plainTextSupplier = abeCPLargeSupplier;
        this.validKeyPair = validKeyPair;
        this.invalidKeyPair = invalidKeyPair;
    }

    public String toString() {
        return encryptionScheme.getClass().getName();
    }

}
