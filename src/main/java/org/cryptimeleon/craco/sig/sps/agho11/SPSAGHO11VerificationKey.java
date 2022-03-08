package org.cryptimeleon.craco.sig.sps.agho11;

import org.cryptimeleon.craco.sig.VerificationKey;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;

import java.util.Arrays;
import java.util.Objects;


/**
 * Class for the public (verification) key of the AGHO11 signature scheme.
 *
 */

public class SPSAGHO11VerificationKey implements VerificationKey {

    /* Note that the generation key GK is included in the verification key in the paper.
            it has been moved to the public parameters here to avoid redundancy */

    /**
     * U_1, ..., U_k_N \in G_1 in the paper.
     */
    @Represented(restorer = "[G1]")
    protected GroupElement[] group1ElementsU;

    /**
     * V \in G_2 in the paper.
     */
    @Represented(restorer = "G2")
    protected GroupElement group2ElementV;

    /**
     * W_1, ..., W_k_M \in G_2 in the paper.
     */
    @Represented(restorer = "[G2]")
    protected GroupElement[] group2ElementsW;

    /**
     * Z \in G_2 in the paper.
     */
    @Represented(restorer = "G2")
    protected GroupElement group2ElementZ;


    public SPSAGHO11VerificationKey() { super(); }

    public SPSAGHO11VerificationKey(GroupElement[] group1ElementsU,
                                    GroupElement group2ElementV,
                                    GroupElement[] group2ElementsW,
                                    GroupElement group2ElementZ) {
        this.group1ElementsU = group1ElementsU;
        this.group2ElementV = group2ElementV;
        this.group2ElementsW = group2ElementsW;
        this.group2ElementZ = group2ElementZ;
    }

    public SPSAGHO11VerificationKey(Group G_1, Group G_2, Representation repr) {
        new ReprUtil(this).register(G_1, "G1").register(G_2, "G2").deserialize(repr);
    }


    public GroupElement[] getGroup1ElementsU() {
        return group1ElementsU;
    }

    public GroupElement getGroup2ElementV() {
        return group2ElementV;
    }

    public GroupElement[] getGroup2ElementsW() {
        return group2ElementsW;
    }

    public GroupElement getGroup2ElementZ() {
        return group2ElementZ;
    }


    @Override
    public Representation getRepresentation() { return ReprUtil.serialize(this); }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        SPSAGHO11VerificationKey that = (SPSAGHO11VerificationKey) o;
        return Arrays.equals(group1ElementsU, that.group1ElementsU)
                && Arrays.equals(group2ElementsW, that.group2ElementsW)
                && Objects.equals(group2ElementV, that.group2ElementV)
                && Objects.equals(group2ElementZ, that.group2ElementZ);
    }

}
