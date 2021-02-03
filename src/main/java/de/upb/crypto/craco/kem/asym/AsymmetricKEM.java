package de.upb.crypto.craco.kem.asym;

import de.upb.crypto.craco.enc.KeyPair;
import de.upb.crypto.craco.kem.KeyEncapsulationMechanism;

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
