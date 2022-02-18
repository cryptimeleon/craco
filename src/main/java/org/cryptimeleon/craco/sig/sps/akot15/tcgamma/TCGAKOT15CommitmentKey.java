package org.cryptimeleon.craco.sig.sps.akot15.tcgamma;

import org.cryptimeleon.craco.commitment.CommitmentKey;
import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.hash.annotations.AnnotatedUbrUtil;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;

public class TCGAKOT15CommitmentKey implements CommitmentKey {

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

}
