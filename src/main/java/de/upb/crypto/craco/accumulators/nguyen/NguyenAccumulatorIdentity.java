package de.upb.crypto.craco.accumulators.nguyen;

import de.upb.crypto.craco.accumulators.interfaces.AccumulatorIdentity;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;
import de.upb.crypto.math.structures.zn.Zp;

public class NguyenAccumulatorIdentity implements AccumulatorIdentity, UniqueByteRepresentable {

    @UniqueByteRepresented
    @Represented(structure = "zp", recoveryMethod = Zp.ZpElement.RECOVERY_METHOD)
    private Zp.ZpElement identity;

    @Represented
    private Zp zp;

    public NguyenAccumulatorIdentity(Zp.ZpElement identity) {
        this.identity = identity;
        this.zp = identity.getStructure();
    }

    public NguyenAccumulatorIdentity(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
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
        if (!(o instanceof NguyenAccumulatorIdentity)) return false;

        NguyenAccumulatorIdentity that = (NguyenAccumulatorIdentity) o;

        if (!identity.equals(that.identity)) return false;
        return zp.equals(that.zp);
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
