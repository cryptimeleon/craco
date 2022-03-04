package org.cryptimeleon.craco.sig.sps.akot15.tc;

import org.cryptimeleon.craco.commitment.Commitment;
import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.structures.groups.GroupElement;

public class TCAKOT15Commitment implements Commitment {

    //TODO Representation?
    private final GroupElement commitment;

    public TCAKOT15Commitment(GroupElement commitment) {
        this.commitment = commitment;
    }

    public GroupElement getCommitment() {
        return commitment;
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return commitment.updateAccumulator(accumulator);
    }

    @Override
    public Representation getRepresentation() {
        return commitment.getRepresentation();
    }

}
