package org.cryptimeleon.craco.sig.sps.agho11;

import org.cryptimeleon.craco.common.PublicParameters;
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
 * Class for the public parameters of the AGHO11 structure preserving signature scheme.
 * Bilinear group type 3
 *
 *
 */

public class SPSAGHO11PublicParameters implements PublicParameters {

    /**
     * The bilinear group containing map e in the paper.
     */
    @Represented
    private BilinearGroup bilinearGroup; // G1 x G2 -> GT

    /**
     * G \in G_1 in paper.
     */
    @Represented(restorer = "bilinearGroup::getG1")
    protected GroupElement group1ElementG;

    /**
     * H \in G_2 in paper.
     */
    @Represented(restorer = "bilinearGroup::getG2")
    protected GroupElement group2ElementH;

    /**
     * The number of expected G1/G2 elements per message respectively
     * */
    @Represented(restorer = "[messageLengths]")
    protected Integer[] messageLengths;


    public SPSAGHO11PublicParameters(BilinearGroup bilinearGroup, Integer[] messageBlockLengths){
        super();
        this.bilinearGroup = bilinearGroup;
        this.messageLengths = messageBlockLengths;
        this.group1ElementG = this.bilinearGroup.getG1().getUniformlyRandomNonNeutral();
        this.group2ElementH = this.bilinearGroup.getG2().getUniformlyRandomNonNeutral();
    }

    public SPSAGHO11PublicParameters(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }




    /**
     * Returns the group Zp (where p is the group order of G1, G2, and GT)
     */
    public Zp getZp() {
        return new Zp(bilinearGroup.getG1().size());
    }

    public GroupElement getG1GroupGenerator(){
        return group1ElementG;
    }

    public GroupElement getG2GroupGenerator(){
        return group2ElementH;
    }

    public BilinearMap getBilinearMap(){ return bilinearGroup.getBilinearMap(); }

    public Group getGT() {return bilinearGroup.getGT(); }

    public Integer[] getMessageLengths(){ return messageLengths; }

    @Override
    public Representation getRepresentation() { return ReprUtil.serialize(this); }

    @Override
    public int hashCode() {
        return Objects.hash(bilinearGroup, group1ElementG, group2ElementH, messageLengths);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        SPSAGHO11PublicParameters that = (SPSAGHO11PublicParameters) o;
        return Objects.equals(bilinearGroup, that.bilinearGroup)
                &&  Objects.equals(group1ElementG, that.group1ElementG)
                &&  Objects.equals(group2ElementH, that.group2ElementH);
    }

}
