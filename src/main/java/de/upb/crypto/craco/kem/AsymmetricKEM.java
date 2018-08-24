package de.upb.crypto.craco.kem;

import de.upb.crypto.craco.interfaces.KeyPair;

public interface AsymmetricKEM<T> extends KeyEncapsulationMechanism<T> {


    KeyPair generateKeyPair();

}
