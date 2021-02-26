package org.cryptimeleon.craco.kem;

import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.hash.UniqueByteRepresentable;

import java.util.Objects;

/**
 * The most basic implementation of a {@link KeyMaterial} based on a {@link UniqueByteRepresentable}.
 * It is extracted from a source of randomness with a well defined amount of min-entropy.
 *
 *
 */
public class UniqueByteKeyMaterial implements KeyMaterial {

    private final UniqueByteRepresentable e;
    private final int minEntropy;

    public UniqueByteKeyMaterial(UniqueByteRepresentable e, int minEntropyOfSource) {
        this.e = e;
        this.minEntropy = minEntropyOfSource;
    }

    public UniqueByteRepresentable getElement() {
        return e;
    }

    @Override
    public int getMinEntropyInBit() {
        return minEntropy;
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        accumulator = e.updateAccumulator(accumulator);
        return accumulator;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        UniqueByteKeyMaterial other = (UniqueByteKeyMaterial) o;
        return minEntropy == other.minEntropy && Objects.equals(e, other.e);
    }

    @Override
    public int hashCode() {
        int result = e.hashCode();
        result = 31 * result + minEntropy;
        return result;
    }
}
