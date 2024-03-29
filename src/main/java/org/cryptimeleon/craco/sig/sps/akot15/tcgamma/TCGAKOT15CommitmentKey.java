package org.cryptimeleon.craco.sig.sps.akot15.tcgamma;

import org.cryptimeleon.craco.commitment.CommitmentKey;
import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.hash.annotations.AnnotatedUbrUtil;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;

import java.util.Arrays;

/**
 * A commitment key generated by the commitment scheme {@link TCGAKOT15CommitmentScheme}.
 *
 */
public class TCGAKOT15CommitmentKey implements CommitmentKey {

    /**
     * X^{tilde}_i \in G_2 in the paper.
     */
    @Represented(restorer = "[G2]")
    private GroupElement[] group2ElementsXi;


    public TCGAKOT15CommitmentKey(GroupElement[] group2ElementsXi) {
        this.group2ElementsXi = group2ElementsXi;
    }

    public TCGAKOT15CommitmentKey(Group group2, Representation repr) {
        new ReprUtil(this).register(group2, "G2").deserialize(repr);
    }


    public GroupElement[] getGroup2ElementsXi() {
        return group2ElementsXi;
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
        TCGAKOT15CommitmentKey that = (TCGAKOT15CommitmentKey) o;
        return Arrays.equals(group2ElementsXi, that.group2ElementsXi);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(group2ElementsXi);
    }

}
