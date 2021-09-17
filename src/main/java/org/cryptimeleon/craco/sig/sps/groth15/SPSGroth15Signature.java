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
import org.cryptimeleon.math.structures.groups.cartesian.GroupElementVector;

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
    @Represented(restorer = "plaintextGroup")
    protected GroupElementVector groupElementSigma3Ti;

    public SPSGroth15Signature(Representation repr, Group plaintextGroup, Group otherGroup) {
        new ReprUtil(this).register(plaintextGroup, "plaintextGroup").register(otherGroup, "otherGroup"). deserialize(repr);
    }

    public SPSGroth15Signature(GroupElement group2ElementSigma1HatR, GroupElement group1ElementSigma2S, GroupElementVector group1ElementSigma3Ti) {
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

    public GroupElement getGroupElementSigma2S() {
        return groupElementSigma2S;
    }

    public GroupElementVector getGroupElementSigma3Ti() {
        return groupElementSigma3Ti;
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
                Objects.equals(groupElementSigma3Ti, that.groupElementSigma3Ti);
    }

    @Override
    public int hashCode() {
        return Objects.hash(groupElementSigma1HatR, groupElementSigma2S, groupElementSigma3Ti);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }
}
