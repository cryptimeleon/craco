package de.upb.crypto.craco.commitment.pedersen;

import de.upb.crypto.craco.commitment.interfaces.OpenValue;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.RepresentedArray;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;
import de.upb.crypto.math.structures.zn.Zn;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

public class PedersenOpenValue implements OpenValue {

    @UniqueByteRepresented
    @Represented
    private BigInteger randomness;

    public PedersenOpenValue(BigInteger randomness) {
        this.randomness = randomness;
    }

    public PedersenOpenValue(Representation representation) {
        new ReprUtil(this).deserialize(representation);
    }

    public BigInteger getRandomValue() {
        return randomness;
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator byteAccumulator) {
        byteAccumulator.append(randomness.toByteArray());
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
