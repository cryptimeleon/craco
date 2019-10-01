package de.upb.crypto.craco.sig.ps18;

import de.upb.crypto.craco.interfaces.PublicParameters;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;
import de.upb.crypto.math.structures.zn.Zp;

/**
 * Class for the public parameters of the Pointcheval Sanders 2018 (Section 4.2)
 * signature scheme.
 *
 * @author Raphael Heitjohann
 */
public class PS18PublicParameters implements PublicParameters {

    /**
     * The bilinear map e in the paper.
     */
    @Represented
    private BilinearMap bilinearMap; // G1 x G2 -> GT

    public PS18PublicParameters(BilinearMap bilinearMap) {
        super();
        this.bilinearMap = bilinearMap;
    }

    public PS18PublicParameters(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    /**
     * @return Field Z_p (where p is the order of G1, G2, and GT).
     */
    public Zp getZp() { return new Zp(bilinearMap.getG1().size()); }

    public BilinearMap getBilinearMap() { return bilinearMap; }

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
        PS18PublicParameters other = (PS18PublicParameters) obj;
        if ((bilinearMap == null) != (other.bilinearMap == null)) {
            return false;
        } else if (!bilinearMap.equals(other.bilinearMap))
            return false;
        return true;
    }
}
