package de.upb.crypto.craco.sig.sps.eq;

import de.upb.crypto.craco.interfaces.PublicParameters;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.RepresentableRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zp;

/**
 * Class for the public parameters of the SPS-EQ signature scheme.
 * Bilinear group type 3
 *
 * @author Fabian Eidens
 */

public class SPSEQPublicParameters implements PublicParameters {

    // The bilinear map e in the paper.
    private BilinearMap bilinearMap; // G1 x G2 -> GT

    /**
     * P \in G_1 in paper.
     */
    protected GroupElement group1ElementP;

    /**
     * \hat{P} \in G_2 in paper.
     */
    protected GroupElement group2ElementHatP;


    public SPSEQPublicParameters(BilinearMap bilinearMap) {
        super();
        this.bilinearMap = bilinearMap;
        this.group1ElementP = this.bilinearMap.getG1().getUniformlyRandomNonNeutral();
        this.group2ElementHatP = this.bilinearMap.getG2().getUniformlyRandomNonNeutral();
    }

    public SPSEQPublicParameters(Representation repr) {
        bilinearMap = (BilinearMap) repr.obj().get("bilinearMap").repr().recreateRepresentable();
        group1ElementP = bilinearMap.getG1().getElement(repr.obj().get("group1ElementP"));
        group2ElementHatP = bilinearMap.getG2().getElement(repr.obj().get("group2ElementHatP"));
    }

    @Override
    public Representation getRepresentation() {
        var result = new ObjectRepresentation();
        result.put("bilinearMap", new RepresentableRepresentation(bilinearMap));
        result.put("group1ElementP", group1ElementP.getRepresentation());
        result.put("group2ElementHatP", group2ElementHatP.getRepresentation());

        return result;
    }

    /**
     * Returns the group Zp (where p is the group order of G1, G2, and GT)
     */
    public Zp getZp() {
        return new Zp(bilinearMap.getG1().size());
    }

    public BilinearMap getBilinearMap() {
        return bilinearMap;
    }

    public GroupElement getGroup1ElementP() {
        return group1ElementP;
    }

    public GroupElement getGroup2ElementHatP() {
        return group2ElementHatP;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((bilinearMap == null) ? 0 : bilinearMap.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        SPSEQPublicParameters other = (SPSEQPublicParameters) obj;
        if ((bilinearMap == null) != (other.bilinearMap == null)) {
            return false;
        } else if (!bilinearMap.equals(other.bilinearMap))
            return false;
        return true;
    }
}
