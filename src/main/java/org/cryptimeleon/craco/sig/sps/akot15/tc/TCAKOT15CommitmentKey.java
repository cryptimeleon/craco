package org.cryptimeleon.craco.sig.sps.akot15.tc;

import org.cryptimeleon.craco.commitment.trapdoorcommitment.CommitmentKey;
import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.hash.annotations.AnnotatedUbrUtil;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.GroupElement;

import java.util.Arrays;

/**
 * Hold a commitment key used by the implementation of the AKOT15 trapdoor commitment scheme.
 * Note that
 * */
public class TCAKOT15CommitmentKey implements CommitmentKey {

    /**
     * X_1, ... , X_l in the paper
     * */
    @Represented
    protected final GroupElement[] group2ElementsX;




    public TCAKOT15CommitmentKey(GroupElement... group2ElementsX) {
        this.group2ElementsX = group2ElementsX;
    }




    public GroupElement[] getGroup2ElementsX() {
        return group2ElementsX;
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }

    @Override
    public Representation getRepresentation() {
        return new ReprUtil(this).serialize();
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TCAKOT15CommitmentKey that = (TCAKOT15CommitmentKey) o;
        return Arrays.equals(group2ElementsX, that.group2ElementsX);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(group2ElementsX);
    }

}
