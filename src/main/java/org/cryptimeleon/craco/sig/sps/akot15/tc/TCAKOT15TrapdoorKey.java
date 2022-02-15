package org.cryptimeleon.craco.sig.sps.akot15.tc;

import org.cryptimeleon.craco.commitment.trapdoorcommitment.TrapdoorKey;
import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.hash.annotations.AnnotatedUbrUtil;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.rings.zn.Zp;
import org.cryptimeleon.math.structures.rings.zn.Zp.ZpElement;

public class TCAKOT15TrapdoorKey implements TrapdoorKey {

    @Represented(restorer = "Zp")
    protected ZpElement[] exponentsRho;

    public TCAKOT15TrapdoorKey(ZpElement... exponentsRho) {
        this.exponentsRho = exponentsRho;
    }

    public TCAKOT15TrapdoorKey(Representation repr, Zp zp) {
        new ReprUtil(this).register(zp, "Zp").deserialize(repr);
    }

    public ZpElement[] getExponentsRho() { return exponentsRho; }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }

    @Override
    public Representation getRepresentation() {
        return new ReprUtil(this).serialize();
    }

}
