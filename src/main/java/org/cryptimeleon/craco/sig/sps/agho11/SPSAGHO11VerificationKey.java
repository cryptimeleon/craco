package org.cryptimeleon.craco.sig.sps.agho11;

import org.cryptimeleon.craco.sig.VerificationKey;
import org.cryptimeleon.craco.sig.sps.eq.SPSEQVerificationKey;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.rings.cartesian.RingElementVector;
import org.cryptimeleon.math.structures.rings.zn.Zp;

import java.util.Arrays;
import java.util.Objects;


/**
 * Class for the public (verification) key of the AGHO11 signature scheme.
 *
 */

public class SPSAGHO11VerificationKey implements VerificationKey {

    // TODO: Note that the generation key GK is included in the verification key in the paper. It has been moved to the public parameters here to avoid redundancy

    /**
     * U_1, ..., U_k_N \in G_1 in the paper.
     */
    @Represented(restorer = "[G1]")
    protected GroupElement[] groupElementsU;

    /**
     * V \in G_2 in the paper.
     */
    @Represented(restorer = "G2")
    protected GroupElement groupElementV;

    /**
     * W_1, ..., W_k_M \in G_2 in the paper.
     */
    @Represented(restorer = "[G2]")
    protected GroupElement[] groupElementsW;

    /**
     * Z \in G_2 in the paper.
     */
    @Represented(restorer = "G2")
    protected GroupElement groupElementZ;




    public SPSAGHO11VerificationKey(){ super(); }

    public SPSAGHO11VerificationKey(Group G_1, Group G_2, Representation repr){
        new ReprUtil(this).register(G_1, "G1").register(G_2, "G2").deserialize(repr);
    }




    public GroupElement[] getGroupElementsU() {
        return groupElementsU;
    }

    public void setGroupElementsU(GroupElement[] groupElementsU) {
        this.groupElementsU = groupElementsU;
    }

    public GroupElement getGroupElementV() {
        return groupElementV;
    }

    public void setGroupElementV(GroupElement groupElementV) {
        this.groupElementV = groupElementV;
    }

    public GroupElement[] getGroupElementsW() {
        return groupElementsW;
    }

    public void setGroupElementsW(GroupElement[] groupElementsW) {
        this.groupElementsW = groupElementsW;
    }

    public GroupElement getGroupElementZ() {
        return groupElementZ;
    }

    public void setGroupElementZ(GroupElement groupElementZ) {
        this.groupElementZ = groupElementZ;
    }




    @Override
    public Representation getRepresentation() { return ReprUtil.serialize(this); }




    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        SPSAGHO11VerificationKey that = (SPSAGHO11VerificationKey) o;
        return Arrays.equals(groupElementsU, that.groupElementsU)
                && Arrays.equals(groupElementsW, that.groupElementsW)
                && Objects.equals(groupElementV, that.groupElementV)
                && Objects.equals(groupElementZ, that.groupElementZ);
    }

}
