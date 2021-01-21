package de.upb.crypto.craco.kem;

import de.upb.crypto.craco.common.interfaces.KeyPair;

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
