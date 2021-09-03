package org.cryptimeleon.craco.sig.sps.groth15;

import org.cryptimeleon.craco.sig.VerificationKey;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;

import java.util.Arrays;
import java.util.Objects;

/**
 * Class for the public (verification) key of the Groth15 SPS signature scheme.
 *
 *
 */

public class SPSGroth15VerificationKey implements VerificationKey {

    /**
     * \{Y}_1, ..., {Y}_l \in the same group as the plaintext in the paper.
     */
    @Represented(restorer = "[plaintextGroup]")
    protected GroupElement[] groupElementsYi;

    /**
     * V \in the group where the plaintext is not from in the paper.
     */
    @Represented(restorer = "otherGroup")
    protected GroupElement groupElementV;


    public SPSGroth15VerificationKey() {
        super();
    }

    public SPSGroth15VerificationKey(Group plaintextGroup, Group otherGroup, Representation repr) {
        new ReprUtil(this).register(plaintextGroup,"plaintextGroup").register(otherGroup, "otherGroup").deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public GroupElement[] getGroupElementsYi() {
        return groupElementsYi;
    }

    public void setGroupElementsYi(GroupElement[] groupElementsYi) {
        this.groupElementsYi = groupElementsYi;
    }

    public GroupElement getGroupElementV() {
        return groupElementV;
    }

    public void setGroupElementV(GroupElement groupElementV) {
        this.groupElementV = groupElementV;
    }


    public int getNumberOfMessages() {
        return groupElementsYi.length;
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SPSGroth15VerificationKey that = (SPSGroth15VerificationKey) o;
        return Arrays.equals(groupElementsYi, that.groupElementsYi)
                && Objects.equals(groupElementV, that.groupElementV);
    }

    @Override
    public int hashCode() {
        return Objects.hash(groupElementsYi, groupElementV);
    }
}
