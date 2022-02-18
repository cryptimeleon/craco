package org.cryptimeleon.craco.sig.sps.akot15;

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
 * The construction of the AKOT FSPS requires the {@link PublicParameters} to match up across building blocks
 * In order to simplify interactions between the schemes, this class holds these shared public parameters
 *
 */
public class AKOT15SharedPublicParameters implements PublicParameters, Cloneable {

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
     * G^{tilde} \in G_2 in paper.
     */
    @Represented(restorer = "bilinearGroup::getG2")
    protected GroupElement group2ElementH;

    @Represented
    protected Integer messageLength;


    public AKOT15SharedPublicParameters() {
        super();
    }

    public AKOT15SharedPublicParameters(BilinearGroup bilinearGroup, int messageLength) {
        super();
        this.bilinearGroup = bilinearGroup;
        this.messageLength = messageLength;

        this.group1ElementG = this.bilinearGroup.getG1().getUniformlyRandomNonNeutral();
        this.group2ElementH = this.bilinearGroup.getG2().getUniformlyRandomNonNeutral();
    }

    public AKOT15SharedPublicParameters(BilinearGroup bilinearGroup,
                                         int messageLength,
                                         GroupElement group1ElementG,
                                         GroupElement group2ElementH) {
        super();
        this.bilinearGroup = bilinearGroup;
        this.messageLength = messageLength;

        this.group1ElementG = group1ElementG;
        this.group2ElementH = group2ElementH;
    }

    public AKOT15SharedPublicParameters(Representation repr) {
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
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof AKOT15SharedPublicParameters)) return false;
        AKOT15SharedPublicParameters that = (AKOT15SharedPublicParameters) o;
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

    @Override
    public AKOT15SharedPublicParameters clone() {

        AKOT15SharedPublicParameters clone = new AKOT15SharedPublicParameters(
                this.bilinearGroup, this.messageLength, this.group1ElementG, group2ElementH
        );

        return clone;
    }

}
