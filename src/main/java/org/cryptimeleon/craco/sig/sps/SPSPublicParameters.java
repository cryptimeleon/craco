package org.cryptimeleon.craco.sig.sps;

import org.cryptimeleon.craco.common.PublicParameters;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearMap;
import org.cryptimeleon.math.structures.rings.zn.Zp;

import java.util.Objects;

/**
 * An interface containing generic components shared by many SPS schemes
 * i.e. a bilinear group for evauating pairing product equations and the associated
 * group generators
 * */
public class SPSPublicParameters implements PublicParameters {

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

    public SPSPublicParameters(BilinearGroup bilinearGroup) {
        super();
        this.bilinearGroup = bilinearGroup;
        this.group1ElementG = this.bilinearGroup.getG1().getUniformlyRandomNonNeutral();
        this.group2ElementH = this.bilinearGroup.getG2().getUniformlyRandomNonNeutral();
    }

    public SPSPublicParameters(Representation repr) {
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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SPSPublicParameters)) return false;
        SPSPublicParameters that = (SPSPublicParameters) o;
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
