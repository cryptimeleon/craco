package org.cryptimeleon.craco.sig.sps.akot15.xsig;

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

import java.util.Objects;

public class SPSXSIGPublicParameters extends AKOT15SharedPublicParameters {

    @Represented(restorer = "bilinearGroup::getG1")
    protected GroupElement group1ElementF1;

    @Represented(restorer = "bilinearGroup::getG1")
    protected GroupElement group1ElementF2;

    @Represented(restorer = "bilinearGroup::getG2")
    protected GroupElement group2ElementF1;

    @Represented(restorer = "bilinearGroup::getG2")
    protected GroupElement group2ElementF2;

    @Represented(restorer = "[bilinearGroup::getG1]")
    protected GroupElement[] group1ElementsU;

    @Represented(restorer = "[bilinearGroup::getG2]")
    protected GroupElement[] group2ElementsU;


    public SPSXSIGPublicParameters(BilinearGroup bilinearGroup, Integer messageLength){
        super(bilinearGroup, messageLength);
        this.bilinearGroup = bilinearGroup;
        this.messageLength = messageLength;
        this.group1ElementG = this.bilinearGroup.getG1().getUniformlyRandomNonNeutral();
        this.group2ElementH = this.bilinearGroup.getG2().getUniformlyRandomNonNeutral();

        generateRandomF();
        generateRandomU();
    }

    public SPSXSIGPublicParameters(AKOT15SharedPublicParameters sharedPP) {
        super(sharedPP.getBilinearGroup(), sharedPP.getMessageLength());
        this.group1ElementG = sharedPP.getG1GroupGenerator();
        this.group2ElementH = sharedPP.getG2GroupGenerator();

        generateRandomF();
        generateRandomU();
    }

    private SPSXSIGPublicParameters(SPSXSIGPublicParameters original) {
        super(original.getBilinearGroup(), original.getMessageLength());
        this.group1ElementG = original.getG1GroupGenerator();
        this.group2ElementH = original.getG2GroupGenerator();

        this.group1ElementF1 = original.group1ElementF1;
        this.group2ElementF1 = original.group2ElementF1;
        this.group1ElementF2 = original.group1ElementF2;
        this.group2ElementF2 = original.group2ElementF2;
        this.group1ElementsU = original.group1ElementsU;
        this.group2ElementsU = original.group2ElementsU;

    }


    public SPSXSIGPublicParameters(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }


    /**
     * Generate the group elements F1, F2 for both groups
     * */
    private void generateRandomF() {

        ZpElement delta = getZp().getUniformlyRandomNonzeroElement();
        ZpElement phi = getZp().getUniformlyRandomNonzeroElement();

        this.group1ElementF1 = group1ElementG.pow(phi).compute();
        this.group2ElementF1 = group2ElementH.pow(phi).compute();

        this.group1ElementF2 = group1ElementG.pow(delta).compute();
        this.group2ElementF2 = group2ElementH.pow(delta).compute();

    }

    private void generateRandomU() {

        this.group1ElementsU = new GroupElement[messageLength];
        this.group2ElementsU = new GroupElement[messageLength];

        for (int i = 0; i < messageLength; i++) {

            ZpElement ui = getZp().getUniformlyRandomNonzeroElement();

            group1ElementsU[i] = group1ElementG.pow(ui).compute();
            group2ElementsU[i] = group2ElementH.pow(ui).compute();
        }

    }


    /**
     * Returns the group Zp (where p is the group order of G1, G2, and GT)
     */
    public Zp getZp(){ return new Zp(bilinearGroup.getG1().size()); }

    public GroupElement getG1GroupGenerator(){
        return group1ElementG;
    }

    public GroupElement getG2GroupGenerator(){
        return group2ElementH;
    }

    public BilinearMap getBilinearMap(){ return bilinearGroup.getBilinearMap(); }

    public Group getGT() {return bilinearGroup.getGT(); }

    public Integer getMessageLength(){ return messageLength; }


    @Override
    public Representation getRepresentation() { return ReprUtil.serialize(this); }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SPSXSIGPublicParameters that = (SPSXSIGPublicParameters) o;
        return Objects.equals(bilinearGroup, that.bilinearGroup)
                && Objects.equals(group1ElementG, that.group1ElementG)
                && Objects.equals(group2ElementH, that.group2ElementH)
                && Objects.equals(messageLength, that.messageLength);
    }

    @Override
    public int hashCode() {
        return Objects.hash(bilinearGroup, group1ElementG, group2ElementH, messageLength);
    }

    @Override
    public SPSXSIGPublicParameters clone() {
        return new SPSXSIGPublicParameters(this);
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

    public void setGroup1ElementG(GroupElement group1ElementG) {
        this.group1ElementG = group1ElementG;
    }

    public GroupElement getGroup2ElementH() {
        return group2ElementH;
    }

    public void setGroup2ElementH(GroupElement group2ElementH) {
        this.group2ElementH = group2ElementH;
    }

    public void setMessageLength(Integer messageLength) {
        this.messageLength = messageLength;
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

}
