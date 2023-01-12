package org.cryptimeleon.craco.sig.ecdsa;

import java.security.KeyPair;
import java.util.Objects;

public class ECDSAKeyPair {
    final ECDSAVerificationKey ecdsaVerificationKey;
    final ECDSASigningKey ecdsaSigningKey;

    public ECDSAKeyPair(KeyPair keyPair) {
        this.ecdsaVerificationKey = new ECDSAVerificationKey(keyPair.getPublic());
        this.ecdsaSigningKey = new ECDSASigningKey(keyPair.getPrivate());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ECDSAKeyPair that = (ECDSAKeyPair) o;
        return Objects.equals(ecdsaVerificationKey, that.ecdsaVerificationKey) && Objects.equals(ecdsaSigningKey, that.ecdsaSigningKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(ecdsaVerificationKey, ecdsaSigningKey);
    }
}
