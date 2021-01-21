package de.upb.crypto.craco.kdf.interfaces;

import de.upb.crypto.craco.kem.KeyMaterial;

/**
 * A randomness source.
 */
public interface SourceOfRandomness {

    /**
     * Returns the amount of currently available randomness.
     */
    public int getOutputLength();

    /**
     * Returns the minimum estimated entropy currently available.
     */
    public int getMinEntropy();

    /**
     * Returns some sampled randomness.
     */
    public KeyMaterial sampleElement();
}
