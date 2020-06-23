package de.upb.crypto.craco.sig.ps;

import de.upb.crypto.craco.interfaces.PublicParameters;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;
import de.upb.crypto.math.structures.zn.Zp;

/**
 * Class for the public parameters of the Pointcheval Sanders signature scheme.
 *
 * @author Fynn Dallmeier
 */

public class PSPublicParameters implements PublicParameters {

    // The bilinear map e in the paper.
    @Represented
    private BilinearMap bilinearMap; // G1 x G2 -> GT
    @Represented
    private Zp zp;

    public PSPublicParameters(BilinearMap bilinearMap) {
        super();
        this.bilinearMap = bilinearMap;
        this.zp = new Zp(bilinearMap.getG1().size());
    }

    public PSPublicParameters(Representation repr) {
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
        return zp;
    }

    public BilinearMap getBilinearMap() {
        return bilinearMap;
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
        PSPublicParameters other = (PSPublicParameters) obj;
        if ((bilinearMap == null) != (other.bilinearMap == null)) {
            return false;
        } else if (!bilinearMap.equals(other.bilinearMap))
            return false;
        return true;
    }
}
