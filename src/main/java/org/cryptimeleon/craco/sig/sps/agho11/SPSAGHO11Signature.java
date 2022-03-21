package org.cryptimeleon.craco.sig.sps.agho11;

import org.cryptimeleon.craco.sig.Signature;
import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.hash.UniqueByteRepresentable;
import org.cryptimeleon.math.hash.annotations.AnnotatedUbrUtil;
import org.cryptimeleon.math.hash.annotations.UniqueByteRepresented;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;

import java.util.Objects;

public class SPSAGHO11Signature implements Signature, UniqueByteRepresentable {

    /**
     * First group element of the signature \in G_1.
     */
    @UniqueByteRepresented
    @Represented(restorer = "G1")
    protected GroupElement group1ElementSigma1R;

    /**
     * Second group element of the signature \in G_1.
     */
    @UniqueByteRepresented
    @Represented(restorer = "G1")
    protected GroupElement group1ElementSigma2S;

    /**
     * Third group element of the signature \in G_2.
     */
    @UniqueByteRepresented
    @Represented(restorer = "G2")
    protected GroupElement group2ElementSigma3T;


    public SPSAGHO11Signature(Representation repr, Group groupG1, Group groupG2) {
        new ReprUtil(this).register(groupG1, "G1").register(groupG2, "G2"). deserialize(repr);
    }

    public SPSAGHO11Signature(GroupElement group1ElementSigma1R,
                              GroupElement group1ElementSigma2S,
                              GroupElement group2ElementSigma3T) {
        super();
        this.group1ElementSigma1R = group1ElementSigma1R;
        this.group1ElementSigma2S = group1ElementSigma2S;
        this.group2ElementSigma3T = group2ElementSigma3T;
    }


    public GroupElement getGroup1ElementSigma1R() {
        return group1ElementSigma1R;
    }

    public GroupElement getGroup1ElementSigma2S() {
        return group1ElementSigma2S;
    }

    public GroupElement getGroup2ElementSigma3T() {
        return group2ElementSigma3T;
    }


    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }

    @Override
    public Representation getRepresentation() { return ReprUtil.serialize(this); }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SPSAGHO11Signature that = (SPSAGHO11Signature) o;
        return Objects.equals(group1ElementSigma1R, that.group1ElementSigma1R)
                && Objects.equals(group1ElementSigma2S, that.group1ElementSigma2S)
                && Objects.equals(group2ElementSigma3T, that.group2ElementSigma3T);
    }

    @Override
    public int hashCode() {
        return Objects.hash(group1ElementSigma1R, group1ElementSigma2S, group2ElementSigma3T);
    }

}
