package org.cryptimeleon.craco.sig.ps;

import org.cryptimeleon.craco.common.PublicParameters;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearMap;
import org.cryptimeleon.math.structures.rings.zn.Zp;

import java.util.Objects;

/**
 * Class for the public parameters of the Pointcheval Sanders signature scheme.
 *
 *
 */

public class PSPublicParameters implements PublicParameters {

    // The bilinear map e in the paper.
    @Represented
    private BilinearGroup bilinearGroup; // G1 x G2 -> GT
    @Represented
    private Zp zp;

    public PSPublicParameters(BilinearGroup bilinearGroup) {
        super();
        this.bilinearGroup = bilinearGroup;
        this.zp = new Zp(bilinearGroup.getG1().size());
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
        return bilinearGroup.getBilinearMap();
    }

    public BilinearGroup getBilinearGroup() {
        return bilinearGroup;
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
        PSPublicParameters that = (PSPublicParameters) other;
        return Objects.equals(bilinearGroup, that.bilinearGroup);
    }
}
