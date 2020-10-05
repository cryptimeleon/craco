package de.upb.crypto.craco.commitment.pedersen;

import de.upb.crypto.craco.commitment.interfaces.OpenValue;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;
import java.util.Objects;

public class PedersenOpenValue implements OpenValue {

    @Represented
    private Zp zp;

    @UniqueByteRepresented
    @Represented(restorer = "[zp]")
    private Zp.ZpElement[] messages;

    @UniqueByteRepresented
    @Represented
    private BigInteger randomness;

    public PedersenOpenValue(BigInteger randomness) {
        this.randomness = randomness;
    }

    public PedersenOpenValue(Representation repr) {
        new ReprUtil(this).deserialize(repr);

    }

    public Zp.ZpElement[] getMessages() {
        return messages;
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
