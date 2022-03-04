package org.cryptimeleon.craco.sig.sps.akot15.xsig;

import org.cryptimeleon.craco.common.PublicParameters;
import org.cryptimeleon.craco.sig.sps.akot15.AKOT15SharedPublicParameters;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearMap;
import org.cryptimeleon.math.structures.rings.zn.Zp;
import org.cryptimeleon.math.structures.rings.zn.Zp.ZpElement;

import java.util.Arrays;
import java.util.Objects;

/**
 * The construction of the AKOT15 signature scheme FSPS2 requires the {@link PublicParameters} to match up
 * across building blocks.
 * This class extends these shared parameters with the elements required in XSIGs calculations.
 *
 */
public class SPSXSIGPublicParameters extends AKOT15SharedPublicParameters {

    /**
     * F_1 \in G_1 in the paper
     */
    @Represented(restorer = "bilinearGroup::getG1")
    protected GroupElement group1ElementF1;

    /**
     * F_2 \in G_1 in the paper
     */
    @Represented(restorer = "bilinearGroup::getG1")
    protected GroupElement group1ElementF2;

    /**
     * F^{tilde}_1 \in G_2 in the paper
     */
    @Represented(restorer = "bilinearGroup::getG2")
    protected GroupElement group2ElementF1;

    /**
     * F^{tilde}_2 \in G_2 in the paper
     */
    @Represented(restorer = "bilinearGroup::getG2")
    protected GroupElement group2ElementF2;

    /**
     * U_i \in G_1 in the paper
     */
    @Represented(restorer = "[bilinearGroup::getG1]")
    protected GroupElement[] group1ElementsU;

    /**
     * U_i \in G_2 in the paper
     */

    @Represented(restorer = "[bilinearGroup::getG2]")
    protected GroupElement[] group2ElementsU;


    public SPSXSIGPublicParameters(BilinearGroup bilinearGroup, int messageLength){
        super(bilinearGroup, messageLength);
        this.bilinearGroup = bilinearGroup;
        this.messageLength = messageLength;
        this.group1ElementG = this.bilinearGroup.getG1().getUniformlyRandomNonNeutral();
        this.group2ElementH = this.bilinearGroup.getG2().getUniformlyRandomNonNeutral();

        generateRandomF();
        generateRandomU();
    }

    public SPSXSIGPublicParameters(AKOT15SharedPublicParameters sharedPP, int messageLength) {
        super(sharedPP.getBilinearGroup(), messageLength);
        this.group1ElementG = sharedPP.getG1GroupGenerator();
        this.group2ElementH = sharedPP.getG2GroupGenerator();

        generateRandomF();
        generateRandomU();
    }

    public SPSXSIGPublicParameters(Representation repr) { super(repr); }


    /**
     * Generate the group elements F_1, F_2 for both groups
     */
    private void generateRandomF() {

        ZpElement delta = getZp().getUniformlyRandomNonzeroElement();
        ZpElement phi = getZp().getUniformlyRandomNonzeroElement();

        this.group1ElementF1 = group1ElementG.pow(phi).compute();
        this.group2ElementF1 = group2ElementH.pow(phi).compute();

        this.group1ElementF2 = group1ElementG.pow(delta).compute();
        this.group2ElementF2 = group2ElementH.pow(delta).compute();

    }

    /**
     * Generate the group elements U_i, U^{tilde}_i for both groups
     */
    private void generateRandomU() {

        this.group1ElementsU = new GroupElement[messageLength];
        this.group2ElementsU = new GroupElement[messageLength];

        for (int i = 0; i < messageLength; i++) {

            ZpElement ui = getZp().getUniformlyRandomNonzeroElement();

            group1ElementsU[i] = group1ElementG.pow(ui).compute();
            group2ElementsU[i] = group2ElementH.pow(ui).compute();
        }

    }


    public BilinearGroup getBilinearGroup() {
        return bilinearGroup;
    }

    public void setBilinearGroup(BilinearGroup bilinearGroup) {
        this.bilinearGroup = bilinearGroup;
    }

  
    public GroupElement getGroup1ElementG() {
        return group1ElementG;
    }

    public GroupElement getGroup2ElementH() {
        return group2ElementH;
    }

    public GroupElement getGroup1ElementF1() {
        return group1ElementF1;
    }

    public GroupElement getGroup1ElementF2() {
        return group1ElementF2;
    }

    public GroupElement getGroup2ElementF1() {
        return group2ElementF1;
    }

    public GroupElement getGroup2ElementF2() {
        return group2ElementF2;
    }

    public GroupElement[] getGroup1ElementsU() {
        return group1ElementsU;
    }

    public GroupElement[] getGroup2ElementsU() {
        return group2ElementsU;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SPSXSIGPublicParameters)) return false;
        if (!super.equals(o)) return false;
        SPSXSIGPublicParameters that = (SPSXSIGPublicParameters) o;
        return Objects.equals(group1ElementF1, that.group1ElementF1)
                && Objects.equals(group1ElementF2, that.group1ElementF2)
                && Objects.equals(group2ElementF1, that.group2ElementF1)
                && Objects.equals(group2ElementF2, that.group2ElementF2)
                && Arrays.equals(group1ElementsU, that.group1ElementsU)
                && Arrays.equals(group2ElementsU, that.group2ElementsU);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(super.hashCode(), group1ElementF1, group1ElementF2, group2ElementF1, group2ElementF2);
        result = 31 * result + Arrays.hashCode(group1ElementsU);
        result = 31 * result + Arrays.hashCode(group2ElementsU);
        return result;
    }
}
