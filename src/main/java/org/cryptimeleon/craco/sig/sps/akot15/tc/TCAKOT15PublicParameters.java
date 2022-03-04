package org.cryptimeleon.craco.sig.sps.akot15.tc;

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

public class TCAKOT15PublicParameters implements PublicParameters {

    /**
     * The bilinear group containing map e in the paper.
     */
    @Represented
    protected BilinearGroup bilinearGroup; // G1 x G2 -> GT

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

    @Represented
    protected Integer messageLength;

    public TCAKOT15PublicParameters(BilinearGroup bilinearGroup, Integer messageLength) {
        super();
        this.bilinearGroup = bilinearGroup;
        this.messageLength = messageLength;
        this.group1ElementG = this.bilinearGroup.getG1().getUniformlyRandomNonNeutral();
        this.group2ElementH = this.bilinearGroup.getG2().getUniformlyRandomNonNeutral();
    }

    public TCAKOT15PublicParameters(Representation repr) {
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

    public int getMessageLength() { return messageLength; }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TCAKOT15PublicParameters)) return false;
        TCAKOT15PublicParameters that = (TCAKOT15PublicParameters) o;
        return Objects.equals(bilinearGroup, that.bilinearGroup) && Objects.equals(group1ElementG, that.group1ElementG) && Objects.equals(group2ElementH, that.group2ElementH);
    }

    @Override
    public int hashCode() {
        return Objects.hash(bilinearGroup, group1ElementG, group2ElementH);
    }

    @Override
    public Representation getRepresentation() {
        return new ReprUtil(this).serialize();
    }
}
