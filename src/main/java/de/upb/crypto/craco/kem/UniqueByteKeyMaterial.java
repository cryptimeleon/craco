package de.upb.crypto.craco.kem;

import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;

/**
 * The most basic implementation of a {@link KeyMaterial}. It encapsulates an
 * element that implements the {@link UniqueByteRepresentable} interface and is
 * extracted from a source of randomness with a well defined amount of
 * min-entropy.
 *
 * @author Jan, refactoring: Mirko Jürgens
 */
public class UniqueByteKeyMaterial implements KeyMaterial {

    private UniqueByteRepresentable e;
    private int minEntropy;

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

        UniqueByteKeyMaterial that = (UniqueByteKeyMaterial) o;

        return minEntropy == that.minEntropy && e.equals(that.e);
    }

    @Override
    public int hashCode() {
        int result = e.hashCode();
        result = 31 * result + minEntropy;
        return result;
    }
}
