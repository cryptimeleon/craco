package org.cryptimeleon.craco.kem.asym;

import org.cryptimeleon.craco.enc.KeyPair;
import org.cryptimeleon.craco.kem.KeyEncapsulationMechanism;

/**
 * A variant of a {@link KeyEncapsulationMechanism} that can also generate asymmetric key pairs via
 * {@link #generateKeyPair()}.
 *
 * @see KeyEncapsulationMechanism
 *
 * @param <T> type of the encapsulated key
 */
public interface AsymmetricKEM<T> extends KeyEncapsulationMechanism<T> {

    KeyPair generateKeyPair();
}
