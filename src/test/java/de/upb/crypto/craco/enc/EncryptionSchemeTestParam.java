package de.upb.crypto.craco.enc;

import de.upb.crypto.craco.common.interfaces.EncryptionScheme;
import de.upb.crypto.craco.common.interfaces.KeyPair;
import de.upb.crypto.craco.common.interfaces.PlainText;

import java.util.function.Supplier;

public class EncryptionSchemeTestParam {

    protected Class<? extends EncryptionScheme> clazz;

    protected EncryptionScheme scheme;

    protected Supplier<PlainText> plainTextSupplier;

    protected KeyPair validKeyPair;

    protected KeyPair invalidKeyPair;

    public EncryptionSchemeTestParam(EncryptionScheme scheme, Supplier<PlainText> plainTextSupplier,
                                     KeyPair validKeyPair, KeyPair invalidKeyPair) {
        this.scheme = scheme;
        this.clazz = scheme.getClass();
        this.plainTextSupplier = plainTextSupplier;
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

    public Supplier<PlainText> getPlainTextSupplier() {
        return plainTextSupplier;
    }

    public KeyPair getValidKeyPair() {
        return validKeyPair;
    }

    public KeyPair getInvalidKeyPair() {
        return invalidKeyPair;
    }
}
