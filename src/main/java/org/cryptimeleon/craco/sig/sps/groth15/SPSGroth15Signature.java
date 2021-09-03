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
    @Represented(restorer = "otherGroup")
    protected GroupElement groupElementSigma1HatR;

    /**
     * Second group element of the signature in G_1.
     */
    @UniqueByteRepresented
    @Represented(restorer = "plaintextGroup")
    protected GroupElement groupElementSigma2S;

    /**
     * Third group element of the signature in G_1.
     */
    @UniqueByteRepresented
    @Represented(restorer = "[plaintextGroup]")
    protected GroupElement[] groupElementSigma3Ti;

    public SPSGroth15Signature(Representation repr, Group plaintextGroup, Group otherGroup) {
        new ReprUtil(this).register(plaintextGroup, "plaintextGroup").register(otherGroup, "otherGroup"). deserialize(repr);
    }

    public SPSGroth15Signature(GroupElement group2ElementSigma1HatR, GroupElement group1ElementSigma2S, GroupElement[] group1ElementSigma3Ti) {
        super();
        this.groupElementSigma1HatR = group2ElementSigma1HatR;
        this.groupElementSigma2S = group1ElementSigma2S;
        this.groupElementSigma3Ti = group1ElementSigma3Ti;
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public GroupElement getGroupElementSigma1HatR() {
        return groupElementSigma1HatR;
    }

    public void setGroupElementSigma1HatR(GroupElement groupElementSigma1HatR) {
        this.groupElementSigma1HatR = groupElementSigma1HatR;
    }

    public GroupElement getGroupElementSigma2S() {
        return groupElementSigma2S;
    }

    public void setGroupElementSigma2S(GroupElement groupElementSigma2S) {
        this.groupElementSigma2S = groupElementSigma2S;
    }

    public GroupElement[] getGroupElementSigma3Ti() {
        return groupElementSigma3Ti;
    }

    public void setGroupElementSigma3Ti(GroupElement[] groupElementSigma3Ti) {
        this.groupElementSigma3Ti = groupElementSigma3Ti;
    }

    @Override
    public String toString() {
        return "SPSGroth15Signature [sigma_1_Hat_R=" + groupElementSigma1HatR + ", sigma_2_S=" + groupElementSigma2S +  ", sigma_3_T" + groupElementSigma3Ti + "]";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SPSGroth15Signature that = (SPSGroth15Signature) o;
        return Objects.equals(groupElementSigma1HatR, that.groupElementSigma1HatR) &&
                Objects.equals(groupElementSigma2S, that.groupElementSigma2S) &&
                Arrays.equals(groupElementSigma3Ti, that.groupElementSigma3Ti);
    }

    @Override
    public int hashCode() {
        return Objects.hash(groupElementSigma1HatR, groupElementSigma2S, Arrays.hashCode(groupElementSigma3Ti));
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }
}
