package org.cryptimeleon.craco.sig.sps.kpw15;

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

import java.util.Arrays;
import java.util.Objects;

public class SPSKPW15Signature implements Signature, UniqueByteRepresentable {

    /**
     * First group element of the signature \in G_1.
     */
    @UniqueByteRepresented
    @Represented(restorer = "[G1]")
    protected GroupElement group1ElementSigma1R[];

    /**
     * Second group element of the signature \in G_1.
     */
    @UniqueByteRepresented
    @Represented(restorer = "[G1]")
    protected GroupElement group1ElementSigma2S[];

    /**
     * Third group element of the signature \in G_1.
     */
    @UniqueByteRepresented
    @Represented(restorer = "[G1]")
    protected GroupElement group1ElementSigma3T[];

    /**
     * Fourth group element of the signature \in G_2.
     */
    @UniqueByteRepresented
    @Represented(restorer = "G2")
    protected GroupElement group2ElementSigma4U;




    public SPSKPW15Signature(Representation repr, Group groupG1, Group groupG2) {
        new ReprUtil(this).register(groupG1,"G1").register(groupG2,"G2").deserialize(repr);
    }

    public SPSKPW15Signature(GroupElement[] group1ElementSigma1R,
                             GroupElement[] group1ElementSigma2S,
                             GroupElement[] group1ElementSigma3T,
                             GroupElement group2ElementSigma4U) {
        super();
        this.group1ElementSigma1R = group1ElementSigma1R;
        this.group1ElementSigma2S = group1ElementSigma2S;
        this.group1ElementSigma3T = group1ElementSigma3T;
        this.group2ElementSigma4U = group2ElementSigma4U;
    }




    public GroupElement[] getGroup1ElementSigma1R() {
        return group1ElementSigma1R;
    }

    public GroupElement[] getGroup1ElementSigma2S() {
        return group1ElementSigma2S;
    }

    public GroupElement[] getGroup1ElementSigma3T() {
        return group1ElementSigma3T;
    }

    public GroupElement getGroup2ElementSigma4U() {
        return group2ElementSigma4U;
    }




    @Override
    public Representation getRepresentation() { return ReprUtil.serialize(this); }


    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) { return AnnotatedUbrUtil.autoAccumulate(accumulator, this); }

    @Override
    public byte[] getUniqueByteRepresentation() {
        return UniqueByteRepresentable.super.getUniqueByteRepresentation();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SPSKPW15Signature that = (SPSKPW15Signature) o;

        return Arrays.equals(group1ElementSigma1R, that.group1ElementSigma1R)
                && Arrays.equals(group1ElementSigma2S, that.group1ElementSigma2S)
                && Arrays.equals(group1ElementSigma3T, that.group1ElementSigma3T)
                && Objects.equals(group2ElementSigma4U, that.group2ElementSigma4U);
    }

    @Override
    public int hashCode() {
        return Objects.hash(group1ElementSigma1R, group1ElementSigma2S, group1ElementSigma3T, group2ElementSigma4U);
    }
}
