package org.cryptimeleon.craco.sig.sps.akot15.tc;

import org.cryptimeleon.craco.commitment.OpenValue;
import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.hash.annotations.AnnotatedUbrUtil;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.rings.zn.Zp.ZpElement;

public class TCAKOT15OpenValue implements OpenValue {

    //TODO Representation?
    private final ZpElement randomness;

    public TCAKOT15OpenValue(ZpElement randomness) {
        this.randomness = randomness;
    }

    public ZpElement getRandomness() {
        return randomness;
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }

    @Override
    public Representation getRepresentation() {
        return randomness.getRepresentation();
    }

}
