package org.cryptimeleon.craco.kem;

import org.cryptimeleon.math.serialization.StandaloneRepresentable;

/**
 * Takes key material and derives something from it
 * (typically a symmetric key).
 *
 * @param <T> type of the resulting derived key
 *
 */
public interface KeyDerivationFunction<T> extends StandaloneRepresentable {
    T deriveKey(KeyMaterial material);
}
