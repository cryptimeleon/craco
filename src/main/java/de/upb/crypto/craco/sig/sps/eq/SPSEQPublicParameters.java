package de.upb.crypto.craco.sig.sps.eq;

import de.upb.crypto.craco.interfaces.PublicParameters;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;

/**
 * Class for the public parameters of the SPS-EQ signature scheme.
 * Bilinear group type 3
 *
 * @author Fabian Eidens
 */

public class SPSEQPublicParameters implements PublicParameters {

    // The bilinear map e in the paper.
    @Represented
    private BilinearMap bilinearMap; // G1 x G2 -> GT

    /**
     * P \in G_1 in paper.
     */
    @Represented(structure = "groupG1", recoveryMethod = GroupElement.RECOVERY_METHOD)
    protected GroupElement group1ElementP;

    /**
     * \hat{P} \in G_2 in paper.
     */
    @Represented(structure = "groupG2", recoveryMethod = GroupElement.RECOVERY_METHOD)
    protected GroupElement group2ElementHatP;


    // pointer field used to store the structure for the representation process; in all other cases this should be null
    protected Group groupG1 = null;
    protected Group groupG2 = null;


    public SPSEQPublicParameters(BilinearMap bilinearMap) {
        super();
        this.bilinearMap = bilinearMap;
        this.group1ElementP = this.bilinearMap.getG1().getUniformlyRandomNonNeutral();
        this.group2ElementHatP = this.bilinearMap.getG2().getUniformlyRandomNonNeutral();
    }

    public SPSEQPublicParameters(Group groupG1, Group groupG2, Representation repr) {
        this.groupG1 = groupG1;
        this.groupG2 = groupG2;
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(repr, this);
        this.groupG1 = null;
        this.groupG2 = null;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
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
