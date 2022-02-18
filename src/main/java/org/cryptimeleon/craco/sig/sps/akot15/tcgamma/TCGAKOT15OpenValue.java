package org.cryptimeleon.craco.sig.sps.akot15.tcgamma;

import org.cryptimeleon.craco.commitment.OpenValue;
import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.hash.annotations.AnnotatedUbrUtil;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;

public class TCGAKOT15OpenValue implements OpenValue {

    /**
     * R in G1 in the paper
     * */
    @Represented(restorer = "G1")
    private GroupElement group1ElementR;


    public TCGAKOT15OpenValue(GroupElement group1ElementR) {
        this.group1ElementR = group1ElementR;
    }

    public TCGAKOT15OpenValue(Group group1, Representation repr) {
        new ReprUtil(this).register(group1, "G1").deserialize(repr);
    }


    public GroupElement getGroup1ElementR() {
        return group1ElementR;
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
