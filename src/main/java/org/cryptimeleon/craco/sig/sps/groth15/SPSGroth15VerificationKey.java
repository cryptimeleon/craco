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
     * \{Y}_1, ..., {Y}_l \in G_1 in paper.
     */
    @Represented(restorer = "[G1]")
    protected GroupElement[] group1ElementsYi;

    /**
     * V \in G_2 in paper.
     */
    @Represented(restorer = "G2")
    protected GroupElement group2ElementV;


    public SPSGroth15VerificationKey() {
        super();
    }

    public SPSGroth15VerificationKey(Group groupG1, Group groupG2, Representation repr) {
        new ReprUtil(this).register(groupG1,"G1").register(groupG2, "G2").deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public GroupElement[] getGroup1ElementsYi() {
        return group1ElementsYi;
    }

    public void setGroup1ElementsYi(GroupElement[] group1ElementsYi) {
        this.group1ElementsYi = group1ElementsYi;
    }

    public GroupElement getGroup2ElementV() {
        return group2ElementV;
    }

    public void setGroup2ElementV(GroupElement group2ElementV) {
        this.group2ElementV = group2ElementV;
    }


    public int getNumberOfMessages() {
        return group1ElementsYi.length;
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SPSGroth15VerificationKey that = (SPSGroth15VerificationKey) o;
        return Arrays.equals(group1ElementsYi, that.group1ElementsYi)
                && Objects.equals(group2ElementV, that.group2ElementV);
    }

    @Override
    public int hashCode() {
        return Objects.hash(group1ElementsYi, group2ElementV);
    }
}
