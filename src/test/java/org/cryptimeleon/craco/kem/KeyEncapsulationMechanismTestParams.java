package org.cryptimeleon.craco.kem;

import org.cryptimeleon.craco.enc.EncryptionKeyPair;

/**
 * Parameter to define a test for {@link KeyEncapsulationMechanismTest}
 */
public class KeyEncapsulationMechanismTestParams {

    protected KeyEncapsulationMechanism kem;
    protected EncryptionKeyPair validKeyPair;
    protected EncryptionKeyPair invalidKeyPair;

    public KeyEncapsulationMechanismTestParams(KeyEncapsulationMechanism kem, EncryptionKeyPair validKeyPair,
                                               EncryptionKeyPair invalidKeyPair) {
        this.kem = kem;
        this.validKeyPair = validKeyPair;
        this.invalidKeyPair = invalidKeyPair;
    }

    public String toString() {
        return kem.getClass().getName();
    }

}