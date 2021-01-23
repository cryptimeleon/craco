package de.upb.crypto.craco.abe.cp.small.asymmetric;

import de.upb.crypto.craco.abe.interfaces.Attribute;
import de.upb.crypto.craco.common.interfaces.PublicParameters;
import de.upb.crypto.math.structures.groups.Group;
import de.upb.crypto.math.structures.groups.GroupElement;
import de.upb.crypto.math.structures.groups.elliptic.BilinearGroup;
import de.upb.crypto.math.structures.groups.elliptic.BilinearMap;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.ReprUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.Map;
import java.util.Objects;

public class ABECPWat11AsymSmallPublicParameters implements PublicParameters {

    @Represented
    private BilinearGroup bilinearGroup;

    @Represented(restorer = "bilinearGroup::getG1")
    private GroupElement g1; // Generator of G_1

    @Represented(restorer = "bilinearGroup::getG2")
    private GroupElement g2; // Generator of G_2

    @Represented(restorer = "bilinearGroup::getGT")
    private GroupElement eGgAlpha; // in G_T

    @Represented(restorer = "bilinearGroup::getG1")
    private GroupElement gA; // in G_1

    @Represented(restorer = "foo -> bilinearGroup::getG1")
    private Map<Attribute, GroupElement> attrs; // Attribute in Universe, Element in G_1

    public ABECPWat11AsymSmallPublicParameters() {

    }


    public ABECPWat11AsymSmallPublicParameters(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    public Group getGroupG1() {
        return bilinearGroup.getG1();
    }

    public Group getGroupG2() {
        return bilinearGroup.getG2();
    }

    public Group getGroupGT() {
        return bilinearGroup.getGT();
    }

    public BilinearMap getE() {
        return bilinearGroup.getBilinearMap();
    }

    public void setBilinearGroup(BilinearGroup bilinearGroup) {
        this.bilinearGroup = bilinearGroup;
    }

    public GroupElement getG1() {
        return g1;
    }

    public void setG1(GroupElement g1) {
        this.g1 = g1;
    }

    public GroupElement getG2() {
        return g2;
    }

    public void setG2(GroupElement g2) {
        this.g2 = g2;
    }

    public GroupElement getEGgAlpha() {
        return eGgAlpha;
    }

    public void setEGgAlpha(GroupElement eGgAlpha) {
        this.eGgAlpha = eGgAlpha;
    }

    public GroupElement getGA() {
        return gA;
    }

    public void setGA(GroupElement gA) {
        this.gA = gA;
    }

    public Map<Attribute, GroupElement> getAttrs() {
        return attrs;
    }

    public void setAttrs(Map<Attribute, GroupElement> attrs) {
        this.attrs = attrs;
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public int hashCode() {
        return Objects.hash(bilinearGroup, g1, g2, eGgAlpha, gA, attrs);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        ABECPWat11AsymSmallPublicParameters other = (ABECPWat11AsymSmallPublicParameters) obj;
        return Objects.equals(bilinearGroup, other.bilinearGroup)
                && Objects.equals(g1, other.g1)
                && Objects.equals(g2, other.g2)
                && Objects.equals(eGgAlpha, other.eGgAlpha)
                && Objects.equals(gA, other.gA)
                && Objects.equals(attrs, other.attrs);
    }
}
