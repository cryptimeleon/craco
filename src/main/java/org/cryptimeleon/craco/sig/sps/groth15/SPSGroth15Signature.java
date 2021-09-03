package org.cryptimeleon.craco.sig.sps.groth15;

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

import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.Objects;

/**
 * Class for a signature of the Groth15 SPS scheme.
 */
public class SPSGroth15Signature implements Signature, UniqueByteRepresentable {

    /**
     * First group element of the signature in G_2.
     */
    @UniqueByteRepresented
    @Represented(restorer = "G2")
    protected GroupElement group2ElementSigma1HatR;

    /**
     * Second group element of the signature in G_1.
     */
    @UniqueByteRepresented
    @Represented(restorer = "G1")
    protected GroupElement group1ElementSigma2S;

    /**
     * Third group element of the signature in G_1.
     */
    @UniqueByteRepresented
    @Represented(restorer = "[G1]")
    protected GroupElement[] group1ElementSigma3Ti;

    public SPSGroth15Signature(Representation repr, Group groupG1, Group groupG2) {
        new ReprUtil(this).register(groupG1, "G1").register(groupG2, "G2"). deserialize(repr);
    }

    public SPSGroth15Signature(GroupElement group2ElementSigma1HatR, GroupElement group1ElementSigma2S, GroupElement[] group1ElementSigma3Ti) {
        super();
        this.group2ElementSigma1HatR = group2ElementSigma1HatR;
        this.group1ElementSigma2S = group1ElementSigma2S;
        this.group1ElementSigma3Ti = group1ElementSigma3Ti;
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public GroupElement getGroup2ElementSigma1HatR() {
        return group2ElementSigma1HatR;
    }

    public void setGroup2ElementSigma1HatR(GroupElement group2ElementSigma1HatR) {
        this.group2ElementSigma1HatR = group2ElementSigma1HatR;
    }

    public GroupElement getGroup1ElementSigma2S() {
        return group1ElementSigma2S;
    }

    public void setGroup1ElementSigma2S(GroupElement group1ElementSigma2S) {
        this.group1ElementSigma2S = group1ElementSigma2S;
    }

    public GroupElement[] getGroup1ElementSigma3Ti() {
        return group1ElementSigma3Ti;
    }

    public void setGroup1ElementSigma3Ti(GroupElement[] group1ElementSigma3Ti) {
        this.group1ElementSigma3Ti = group1ElementSigma3Ti;
    }

    @Override
    public String toString() {
        return "SPSGroth15Signature [sigma_1_Hat_R=" + group2ElementSigma1HatR + ", sigma_2_S=" + group1ElementSigma2S +  ", sigma_3_T" + group1ElementSigma3Ti + "]";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SPSGroth15Signature that = (SPSGroth15Signature) o;
        return Objects.equals(group2ElementSigma1HatR, that.group2ElementSigma1HatR) &&
                Objects.equals(group1ElementSigma2S, that.group1ElementSigma2S) &&
                Arrays.equals(group1ElementSigma3Ti, that.group1ElementSigma3Ti);
    }

    @Override
    public int hashCode() {
        return Objects.hash(group2ElementSigma1HatR, group1ElementSigma2S, Arrays.hashCode(group1ElementSigma3Ti));
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }
}
