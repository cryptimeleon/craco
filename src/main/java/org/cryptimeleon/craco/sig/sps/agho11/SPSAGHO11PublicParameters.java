package org.cryptimeleon.craco.sig.sps.agho11;

import org.cryptimeleon.craco.common.PublicParameters;
import org.cryptimeleon.craco.sig.sps.SPSPublicParameters;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearMap;
import org.cryptimeleon.math.structures.rings.zn.Zp;

import java.util.Arrays;
import java.util.Objects;

/**
 * Class for the public parameters of the AGHO11 structure preserving signature scheme.
 * Bilinear group type 3
 *
 *
 */

public class SPSAGHO11PublicParameters extends SPSPublicParameters {

    /**
     * The number of expected G1/G2 elements per message respectively
     * */
    @Represented(restorer = "[messageLengths]")
    protected Integer[] messageLengths;


    public SPSAGHO11PublicParameters(BilinearGroup bilinearGroup, Integer[] messageBlockLengths){
        // as SPSPublicParameters precompute G and H itself, we do not need to precompute here
        super(bilinearGroup);
        this.messageLengths = messageBlockLengths;
    }

    public SPSAGHO11PublicParameters(Representation repr)
    {
        new ReprUtil(this).deserialize(repr);
    }


    public Integer[] getMessageLengths(){ return messageLengths; }


    @Override
    public Representation getRepresentation() { return ReprUtil.serialize(this); }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        SPSAGHO11PublicParameters that = (SPSAGHO11PublicParameters) o;
        return Arrays.equals(messageLengths, that.messageLengths);
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + Arrays.hashCode(messageLengths);
        return result;
    }
}
