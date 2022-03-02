package org.cryptimeleon.craco.sig.sps.akot15.tcgamma;

import org.cryptimeleon.craco.commitment.Commitment;
import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.hash.annotations.AnnotatedUbrUtil;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;

import java.util.Objects;

public class TCGAKOT15Commitment implements Commitment {

    /**
     * G_u in G2 in the paper
     * */
    @Represented(restorer = "G2")
    private GroupElement group2ElementGu;


    public TCGAKOT15Commitment(GroupElement group2ElementGu) {
        this.group2ElementGu = group2ElementGu;
    }

    public TCGAKOT15Commitment(Group group2, Representation repr) {
        new ReprUtil(this).register(group2, "G2").deserialize(repr);
    }


    public GroupElement getGroup2ElementGu() {
        return group2ElementGu;
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
        if (!(o instanceof TCGAKOT15Commitment)) return false;
        TCGAKOT15Commitment that = (TCGAKOT15Commitment) o;
        return Objects.equals(group2ElementGu, that.group2ElementGu);
    }

    @Override
    public int hashCode() {
        return Objects.hash(group2ElementGu);
    }
}
