package org.cryptimeleon.craco.sig.sps.kpw15;

import org.cryptimeleon.craco.common.PublicParameters;
import org.cryptimeleon.craco.sig.sps.agho11.SPSAGHO11PublicParameters;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearMap;
import org.cryptimeleon.math.structures.rings.zn.Zp;

import java.util.Objects;

/**
 * Class for the public parameters of the KPW15 structure preserving signature scheme.
 * Uses Bilinear group type 3
 *
 * */
public class SPSKPW15PublicParameters implements PublicParameters {

    /**
     * The bilinear group containing map e in the paper.
     */
    @Represented
    private BilinearGroup bilinearGroup;

    /**
     * g_1 \in G_1 in paper.
     */
    @Represented(restorer = "bilinearGroup::getG1")
    protected GroupElement group1ElementG;

    /**
     * g_2 \in G_2 in paper.
     */
    @Represented(restorer = "bilinearGroup::getG2")
    protected GroupElement group2ElementH;

    /**
     * The number of expected G_1 elements per message
     * */
    @Represented(restorer = "messageLength")
    protected int messageLength;

    public SPSKPW15PublicParameters(BilinearGroup bilinearGroup, int messageLength){
        super();
        this.bilinearGroup = bilinearGroup;
        this.messageLength = messageLength;
        this.group1ElementG = this.bilinearGroup.getG1().getUniformlyRandomNonNeutral();
        this.group2ElementH = this.bilinearGroup.getG2().getUniformlyRandomNonNeutral();
    }

    public SPSKPW15PublicParameters(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }




    public Zp getZp() { return new Zp(bilinearGroup.getG1().size()); }

    public GroupElement getG1GroupGenerator() { return group1ElementG; }

    public GroupElement getG2GroupGenerator() { return group2ElementH; }

    public Group getGT() { return bilinearGroup.getGT(); }

    public BilinearMap getBilinearMap(){ return bilinearGroup.getBilinearMap(); }

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
