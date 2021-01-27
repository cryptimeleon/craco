package de.upb.crypto.craco.commitment.pedersen;

import de.upb.crypto.craco.commitment.OpenValue;
import de.upb.crypto.math.hash.ByteAccumulator;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.ReprUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.rings.zn.Zn;

import java.util.Objects;

public class PedersenOpenValue implements OpenValue {
    @UniqueByteRepresented
    @Represented(restorer = "zn")
    private Zn.ZnElement randomness;

    public PedersenOpenValue(Zn.ZnElement randomness) {
        this.randomness = randomness;
    }

    public Zn.ZnElement getRandomValue() {
        return randomness;
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
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
