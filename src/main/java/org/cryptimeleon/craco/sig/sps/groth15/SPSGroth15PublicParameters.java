package org.cryptimeleon.craco.sig.sps.groth15;

import org.cryptimeleon.craco.common.PublicParameters;
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
import java.util.stream.IntStream;

/**
 * Class for the public parameters of the simplified Groth15 SPS signature scheme.
 * Bilinear group type 3
 *
 *
 */

public class SPSGroth15PublicParameters implements PublicParameters {

    @Represented
    protected SPSGroth15PublicParametersGen.Groth15Type type;

    /**
     * The bilinear group containing map e in the paper.
      */
    @Represented
    private BilinearGroup bilinearGroup; // G1 x G2 -> GT

    /**
     * g (g_1) \in G_1 in paper.
     */
    @Represented(restorer = "bilinearGroup::getG1")
    protected GroupElement group1ElementG;

    /**
     * g_2 (\hat(g)) \in G_2 in paper.
     */
    @Represented(restorer = "bilinearGroup::getG2")
    protected GroupElement group2ElementHatG;

    /**
     * \{Y}_1, ..., {Y}_l \in the same group as the plaintext in the paper.
     */
    @Represented(restorer = "[plaintextGroup]")
    protected GroupElement[] groupElementsYi;

    public SPSGroth15PublicParameters(BilinearGroup bilinearGroup, SPSGroth15PublicParametersGen.Groth15Type type, int numberOfMessages) {
        super();
        this.bilinearGroup = bilinearGroup;
        this.group1ElementG = this.bilinearGroup.getG1().getUniformlyRandomNonNeutral();
        this.group2ElementHatG = this.bilinearGroup.getG2().getUniformlyRandomNonNeutral();
        this.type = type;

        // Y_i's in paper
        GroupElement plaintextGroupElement = getPlaintextGroupGenerator();
        this.groupElementsYi = IntStream.range(0, numberOfMessages).mapToObj(a -> plaintextGroupElement.getStructure().getUniformlyRandomElement())
                .toArray(GroupElement[]::new);
    }

    public SPSGroth15PublicParameters(Representation repr) {
        new ReprUtil(this)
                .register(r -> type == SPSGroth15PublicParametersGen.Groth15Type.type1 ? bilinearGroup.getG1().restoreElement(r) : bilinearGroup.getG2().restoreElement(r), "plaintextGroup")
                .deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    /**
     * Returns the group Zp (where p is the group order of G1, G2, and GT)
     */
    public Zp getZp() {
        return new Zp(bilinearGroup.getG1().size());
    }

    public BilinearMap getBilinearMap() {
        return bilinearGroup.getBilinearMap();
    }

    public GroupElement[] getGroupElementsYi() {
        return groupElementsYi;
    }

    public void setGroupElementsYi(GroupElement[] groupElementsYi) {
        this.groupElementsYi = groupElementsYi;
    }

    public GroupElement getPlaintextGroupGenerator() {
        if(type == SPSGroth15PublicParametersGen.Groth15Type.type1) {
            return group1ElementG;
        }
        else{
            return group2ElementHatG;
        }
    }

    public GroupElement getOtherGroupGenerator() {
        if(type == SPSGroth15PublicParametersGen.Groth15Type.type1) {
            return group2ElementHatG;
        }
        else{
            return group1ElementG;
        }
    }

    public int getNumberOfMessages() {
        return groupElementsYi.length;
    }

    @Override
    public int hashCode() {
        return Objects.hash(Arrays.hashCode(groupElementsYi),bilinearGroup);
    }

    @Override
    public boolean equals(Object other) {
        if (this == other)
            return true;
        if (other == null || getClass() != other.getClass())
            return false;
        SPSGroth15PublicParameters that = (SPSGroth15PublicParameters) other;
        return Objects.equals(bilinearGroup, that.bilinearGroup)
                && Objects.equals(group1ElementG, that.group1ElementG)
                && Objects.equals(group2ElementHatG, that.group2ElementHatG)
                && Arrays.equals(groupElementsYi, that.groupElementsYi);
    }
}
