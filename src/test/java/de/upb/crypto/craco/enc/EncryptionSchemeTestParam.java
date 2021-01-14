package de.upb.crypto.craco.enc;

import de.upb.crypto.craco.common.interfaces.EncryptionScheme;
import de.upb.crypto.craco.common.interfaces.KeyPair;
import de.upb.crypto.craco.common.interfaces.PlainText;

/**
 * Parameters for use with {@link EncryptionSchemeTester}.
 */
public class EncryptionSchemeTestParam {

    /**
     * The class of the scheme.
     */
    protected Class<? extends EncryptionScheme> clazz;

    /**
     * The scheme these parameters are for.
     */
    protected EncryptionScheme scheme;

    /**
     * The plaintext to use in the tests.
     */
    protected PlainText plainText;

    /**
     * The valid keypair to use in the tests.
     */
    protected KeyPair validKeyPair;

    /**
     * An invalid key pair, meaning one that does not allow for correct decryption.
     */
    protected KeyPair invalidKeyPair;

    public EncryptionSchemeTestParam(EncryptionScheme scheme, PlainText plainText,
                                     KeyPair validKeyPair, KeyPair invalidKeyPair) {
        this.scheme = scheme;
        this.clazz = scheme.getClass();
        this.plainText = plainText;
        this.validKeyPair = validKeyPair;
        this.invalidKeyPair = invalidKeyPair;
    }

    public EncryptionSchemeTestParam(Class<? extends EncryptionScheme> clazz) {
        this.clazz = clazz;
    }

    public Class<? extends EncryptionScheme> getClazz() {
        return clazz;
    }

    public EncryptionScheme getScheme() {
        return scheme;
    }

    public PlainText getPlainText() {
        return plainText;
    }

    public KeyPair getValidKeyPair() {
        return validKeyPair;
    }

    public KeyPair getInvalidKeyPair() {
        return invalidKeyPair;
    }
}
