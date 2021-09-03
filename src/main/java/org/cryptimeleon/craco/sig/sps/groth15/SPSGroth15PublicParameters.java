package org.cryptimeleon.craco.sig.sps.groth15;

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
 * Class for the public parameters of the simplified Groth15 SPS signature scheme.
 * Bilinear group type 3
 *
 *
 */

public class SPSGroth15PublicParameters implements PublicParameters {

    /**
     * The bilinear group containing map e in the paper.
      */
    @Represented
    private BilinearGroup bilinearGroup; // G1 x G2 -> GT

    /**
     * g (g_1) \in G_1 in paper.
     */
    @Represented(restorer = "bilinearGroup::getG1")
    protected GroupElement group1ElementG;

    /**
     * g_2 (\hat(g)) \in G_2 in paper.
     */
    @Represented(restorer = "bilinearGroup::getG2")
    protected GroupElement group2ElementHatG;


    public SPSGroth15PublicParameters(BilinearGroup bilinearGroup) {
        super();
        this.bilinearGroup = bilinearGroup;
        this.group1ElementG = this.bilinearGroup.getG1().getUniformlyRandomNonNeutral();
        this.group2ElementHatG = this.bilinearGroup.getG2().getUniformlyRandomNonNeutral();
    }

    public SPSGroth15PublicParameters(Representation repr) {
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

    public GroupElement getGroup1ElementG() {
        return group1ElementG;
    }

    public GroupElement getGroup2ElementHatG() {
        return group2ElementHatG;
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
        SPSGroth15PublicParameters that = (SPSGroth15PublicParameters) other;
        return Objects.equals(bilinearGroup, that.bilinearGroup)
                && Objects.equals(group1ElementG, that.group1ElementG)
                && Objects.equals(group2ElementHatG, that.group2ElementHatG);
    }
}
