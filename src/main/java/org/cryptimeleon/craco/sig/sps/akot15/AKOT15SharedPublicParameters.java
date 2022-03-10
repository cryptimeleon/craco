package org.cryptimeleon.craco.sig.sps.akot15;

import org.cryptimeleon.craco.common.PublicParameters;
import org.cryptimeleon.craco.sig.sps.SPSPublicParameters;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearMap;
import org.cryptimeleon.math.structures.rings.zn.Zp;

import java.util.Objects;

/**
 * The construction of the AKOT15 signature scheme
 * {@link org.cryptimeleon.craco.sig.sps.akot15.fsp2.SPSFSP2SignatureScheme} requires the {@link PublicParameters}
 * to match up across building blocks. In order to simplify interactions between the schemes,
 * this class holds these shared public parameters.
 *
 */
public class AKOT15SharedPublicParameters extends SPSPublicParameters implements Cloneable {

    @Represented
    protected Integer messageLength;


    public AKOT15SharedPublicParameters(BilinearGroup bilinearGroup, int messageLength) {
        super(bilinearGroup);
        this.bilinearGroup = bilinearGroup;
        this.messageLength = messageLength;

        this.group1ElementG = this.bilinearGroup.getG1().getUniformlyRandomNonNeutral();
        this.group2ElementH = this.bilinearGroup.getG2().getUniformlyRandomNonNeutral();
    }

    public AKOT15SharedPublicParameters(BilinearGroup bilinearGroup,
                                         int messageLength,
                                         GroupElement group1ElementG,
                                         GroupElement group2ElementH) {
        super(bilinearGroup);
        this.bilinearGroup = bilinearGroup;
        this.messageLength = messageLength;

        this.group1ElementG = group1ElementG;
        this.group2ElementH = group2ElementH;
    }

    public AKOT15SharedPublicParameters(Representation repr) {
        super(repr);
    }


    public BilinearGroup getBilinearGroup() {
        return bilinearGroup;
    }

    public BilinearMap getBilinearMap(){ return bilinearGroup.getBilinearMap(); }

    public Integer getMessageLength() {
        return messageLength;
    }

    public void setMessageLength(int messageLength) {
        this.messageLength = messageLength;
    }


    @Override
    public Representation getRepresentation() {
        return new ReprUtil(this).serialize();
    }

    @Override
    public AKOT15SharedPublicParameters clone() {

        AKOT15SharedPublicParameters clone = new AKOT15SharedPublicParameters(
                this.bilinearGroup, this.messageLength, this.group1ElementG, group2ElementH
        );

        return clone;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof AKOT15SharedPublicParameters)) return false;
        if (!super.equals(o)) return false;
        AKOT15SharedPublicParameters that = (AKOT15SharedPublicParameters) o;
        return Objects.equals(messageLength, that.messageLength);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), messageLength);
    }

}
