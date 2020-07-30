package de.upb.crypto.craco.sig.sps.eq;

import de.upb.crypto.craco.interfaces.PublicParameters;
import de.upb.crypto.math.factory.BilinearGroup;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.RepresentableRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.Objects;

/**
 * Class for the public parameters of the SPS-EQ signature scheme.
 * Bilinear group type 3
 *
 * @author Fabian Eidens
 */

public class SPSEQPublicParameters implements PublicParameters {

    /**
     * The bilinear group containing map e in the paper.
      */
    private BilinearGroup bilinearGroup; // G1 x G2 -> GT

    /**
     * P \in G_1 in paper.
     */
    protected GroupElement group1ElementP;

    /**
     * \hat{P} \in G_2 in paper.
     */
    protected GroupElement group2ElementHatP;


    public SPSEQPublicParameters(BilinearGroup bilinearGroup) {
        super();
        this.bilinearGroup = bilinearGroup;
        this.group1ElementP = this.bilinearGroup.getG1().getUniformlyRandomNonNeutral();
        this.group2ElementHatP = this.bilinearGroup.getG2().getUniformlyRandomNonNeutral();
    }

    public SPSEQPublicParameters(Representation repr) {
        bilinearGroup = (BilinearGroup) repr.obj().get("bilinearGroup").repr().recreateRepresentable();
        group1ElementP = bilinearGroup.getG1().getElement(repr.obj().get("group1ElementP"));
        group2ElementHatP = bilinearGroup.getG2().getElement(repr.obj().get("group2ElementHatP"));
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation result = new ObjectRepresentation();
        result.put("bilinearGroup", new RepresentableRepresentation(bilinearGroup));
        result.put("group1ElementP", group1ElementP.getRepresentation());
        result.put("group2ElementHatP", group2ElementHatP.getRepresentation());

        return result;
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
