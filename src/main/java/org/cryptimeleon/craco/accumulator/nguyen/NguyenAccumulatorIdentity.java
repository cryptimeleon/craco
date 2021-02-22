package org.cryptimeleon.craco.accumulator.nguyen;

import org.cryptimeleon.craco.accumulator.AccumulatorIdentity;
import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.hash.UniqueByteRepresentable;
import org.cryptimeleon.math.hash.annotations.AnnotatedUbrUtil;
import org.cryptimeleon.math.hash.annotations.UniqueByteRepresented;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.rings.zn.Zp;

import java.util.Objects;

public class NguyenAccumulatorIdentity implements AccumulatorIdentity, UniqueByteRepresentable {

    @UniqueByteRepresented
    @Represented(restorer = "zp")
    private Zp.ZpElement identity;

    @Represented
    private Zp zp;

    public NguyenAccumulatorIdentity(Zp.ZpElement identity) {
        this.identity = identity;
        this.zp = identity.getStructure();
    }

    public NguyenAccumulatorIdentity(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    public Zp.ZpElement getIdentity() {
        return identity;
    }

    public Zp getZp() {
        return zp;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        NguyenAccumulatorIdentity other = (NguyenAccumulatorIdentity) o;
        return Objects.equals(identity, other.identity)
                && Objects.equals(zp, other.zp);
    }

    @Override
    public int hashCode() {
        int result = identity.hashCode();
        result = 31 * result + zp.hashCode();
        return result;
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }
}
