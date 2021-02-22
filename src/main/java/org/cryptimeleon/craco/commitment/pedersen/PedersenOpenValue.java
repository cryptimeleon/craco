package org.cryptimeleon.craco.commitment.pedersen;

import org.cryptimeleon.craco.commitment.OpenValue;
import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.structures.rings.zn.Zn;

import java.util.Objects;

public class PedersenOpenValue implements OpenValue {
    private final Zn.ZnElement randomness;

    public PedersenOpenValue(Zn.ZnElement randomness) {
        this.randomness = randomness;
    }

    public Zn.ZnElement getRandomValue() {
        return randomness;
    }

    @Override
    public Representation getRepresentation() {
        return randomness.getRepresentation();
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator byteAccumulator) {
        byteAccumulator.append(randomness);
        return byteAccumulator;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PedersenOpenValue that = (PedersenOpenValue) o;
        return randomness.equals(that.randomness);
    }

    @Override
    public int hashCode() {
        return Objects.hash(randomness);
    }
}
