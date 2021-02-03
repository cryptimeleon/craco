package de.upb.crypto.craco.kem;

import de.upb.crypto.craco.enc.KeyPair;

/**
 * Parameter to define a test for {@link KeyEncapsulationMechanismTest}
 */
public class KeyEncapsulationMechanismTestParams {

    protected KeyEncapsulationMechanism kem;
    protected KeyPair validKeyPair;
    protected KeyPair invalidKeyPair;

    public KeyEncapsulationMechanismTestParams(KeyEncapsulationMechanism kem, KeyPair validKeyPair,
                                               KeyPair invalidKeyPair) {
        this.kem = kem;
        this.validKeyPair = validKeyPair;
        this.invalidKeyPair = invalidKeyPair;
    }

    public String toString() {
        return kem.getClass().getName();
    }

}