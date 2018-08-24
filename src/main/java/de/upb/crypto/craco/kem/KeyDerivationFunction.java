package de.upb.crypto.craco.kem;

import de.upb.crypto.math.serialization.StandaloneRepresentable;

/**
 * Takes key material and derives something from it
 * (most typically a symmetric key)
 *
 * @param <T>
 * @author Jan
 */
public interface KeyDerivationFunction<T> extends StandaloneRepresentable {
    T deriveKey(KeyMaterial material);
}
