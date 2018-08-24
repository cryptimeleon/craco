package de.upb.crypto.craco.interfaces.kdf;

import de.upb.crypto.craco.kem.KeyMaterial;

public interface SourceOfRandomness {

    public int getOutputLength();

    public int getMinEntropy();

    public KeyMaterial sampleElement();
}
