package org.cryptimeleon.craco.sig.sps.eq;

import org.cryptimeleon.craco.common.PublicParameters;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearMap;
import org.cryptimeleon.math.structures.rings.zn.Zp;

import java.util.Objects;

/**
 * Class for the public parameters of the SPS-EQ signature scheme.
 * Bilinear group type 3
 *
 *
 */

public class SPSEQPublicParameters implements PublicParameters {

    /**
     * The bilinear group containing map e in the paper.
      */
    @Represented
    private BilinearGroup bilinearGroup; // G1 x G2 -> GT

    /**
     * P \in G_1 in paper.
     */
    @Represented(restorer = "bilinearGroup::getG1")
    protected GroupElement group1ElementP;

    /**
     * \hat{P} \in G_2 in paper.
     */
    @Represented(restorer = "bilinearGroup::getG2")
    protected GroupElement group2ElementHatP;


    public SPSEQPublicParameters(BilinearGroup bilinearGroup) {
        super();
        this.bilinearGroup = bilinearGroup;
        this.group1ElementP = this.bilinearGroup.getG1().getUniformlyRandomNonNeutral();
        this.group2ElementHatP = this.bilinearGroup.getG2().getUniformlyRandomNonNeutral();
    }

    public SPSEQPublicParameters(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    /**
     * Returns the group Zp (where p is the group order of G1, G2, and GT)
     */
    public Zp getZp() {
        return new Zp(bilinearGroup.getG1().size());
    }

    public BilinearMap getBilinearMap() {
        return bilinearGroup.getBilinearMap();
    }

    public GroupElement getGroup1ElementP() {
        return group1ElementP;
    }

    public GroupElement getGroup2ElementHatP() {
        return group2ElementHatP;
    }

    @Override
    public int hashCode() {
        return Objects.hash(bilinearGroup);
    }

    @Override
    public boolean equals(Object other) {
        if (this == other)
            return true;
        if (other == null || getClass() != other.getClass())
            return false;
        SPSEQPublicParameters that = (SPSEQPublicParameters) other;
        return Objects.equals(bilinearGroup, that.bilinearGroup);
    }
}
