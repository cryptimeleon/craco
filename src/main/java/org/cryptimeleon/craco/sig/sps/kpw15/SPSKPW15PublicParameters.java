package org.cryptimeleon.craco.sig.sps.kpw15;

import org.cryptimeleon.craco.sig.sps.SPSPublicParameters;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;

import java.util.Objects;

/**
 * Class for the public parameters of the KPW15 structure preserving signature scheme.
 * Uses Bilinear group type 3
 *
 * */
public class SPSKPW15PublicParameters extends SPSPublicParameters {

    /**
     * The number of expected G_1 elements per message
     * */
    @Represented(restorer = "messageLength")
    protected Integer messageLength;

    public SPSKPW15PublicParameters(BilinearGroup bilinearGroup, int messageLength){
        super(bilinearGroup);
        this.messageLength = messageLength;
    }

    public SPSKPW15PublicParameters(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }


    public int getMessageLength() { return messageLength; }


    @Override
    public Representation getRepresentation() { return ReprUtil.serialize(this); }

    @Override
    public int hashCode() {
        return Objects.hash(bilinearGroup, group1ElementG, group2ElementH, messageLength);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        SPSKPW15PublicParameters that = (SPSKPW15PublicParameters) o;
        return Objects.equals(bilinearGroup, that.bilinearGroup)
                &&  Objects.equals(group1ElementG, that.group1ElementG)
                &&  Objects.equals(group2ElementH, that.group2ElementH)
                &&  messageLength == that.messageLength;
    }

}