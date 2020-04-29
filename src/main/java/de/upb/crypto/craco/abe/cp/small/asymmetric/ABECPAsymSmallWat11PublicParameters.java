package de.upb.crypto.craco.abe.cp.small.asymmetric;

import de.upb.crypto.craco.interfaces.PublicParameters;
import de.upb.crypto.craco.interfaces.abe.Attribute;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

import java.util.Map;

public class ABECPAsymSmallWat11PublicParameters implements PublicParameters {

    @Represented
    private Group groupG1, groupG2, groupGT;

    @Represented
    private BilinearMap e;

    @Represented(restorer = "groupG1")
    private GroupElement g1; // Generator of G_1

    @Represented(restorer = "groupG1")
    private GroupElement g2; // Generator of G_2

    @Represented(restorer = "groupGT")
    private GroupElement eGgAlpha; // in G_T

    @Represented(restorer = "groupG1")
    private GroupElement gA; // in G_1

    @Represented(restorer = "foo -> groupG1")
    private Map<Attribute, GroupElement> attrs; // Attribute in Universe, Element in G_1

    public ABECPAsymSmallWat11PublicParameters() {

    }


    public ABECPAsymSmallWat11PublicParameters(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    public Group getGroupG1() {
        return groupG1;
    }

    public void setGroupG1(Group groupG1) {
        this.groupG1 = groupG1;
    }

    public Group getGroupG2() {
        return groupG2;
    }

    public void setGroupG2(Group groupG2) {
        this.groupG2 = groupG2;
    }

    public Group getGroupGT() {
        return groupGT;
    }

    public void setGroupGT(Group groupGT) {
        this.groupGT = groupGT;
    }

    public BilinearMap getE() {
        return e;
    }

    public void setE(BilinearMap e) {
        this.e = e;
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

    public GroupElement geteGgAlpha() {
        return eGgAlpha;
    }

    public void seteGgAlpha(GroupElement eGgAlpha) {
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
        final int prime = 31;
        int result = 1;
        result = prime * result + ((e == null) ? 0 : e.hashCode());
        result = prime * result + ((g1 == null) ? 0 : g1.hashCode());
        result += prime * result + ((g2 == null) ? 0 : g2.hashCode());
        result = prime * result + ((gA == null) ? 0 : gA.hashCode());
        result = prime * result + ((groupG1 == null) ? 0 : groupG1.hashCode());
        result = prime * result + ((groupGT == null) ? 0 : groupGT.hashCode());
        result = prime * result + ((attrs == null) ? 0 : attrs.hashCode());
        result = prime * result + ((eGgAlpha == null) ? 0 : eGgAlpha.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        ABECPAsymSmallWat11PublicParameters other = (ABECPAsymSmallWat11PublicParameters) obj;
        if (e == null) {
            if (other.e != null)
                return false;
        } else if (!e.equals(other.e))
            return false;
        if (g1 == null) {
            if (other.g1 != null)
                return false;
        } else if (!g1.equals(other.g1))
            return false;
        if (g2 == null) {
            if (other.g2 != null)
                return false;
        } else if (!g2.equals(other.g2))
            return false;
        if (gA == null) {
            if (other.gA != null)
                return false;
        } else if (!gA.equals(other.gA))
            return false;
        if (groupG1 == null) {
            if (other.groupG1 != null)
                return false;
        } else if (!groupG1.equals(other.groupG1))
            return false;
        if (groupGT == null) {
            if (other.groupGT != null)
                return false;
        } else if (!groupGT.equals(other.groupGT))
            return false;
        if (attrs == null) {
            if (other.attrs != null)
                return false;
        } else if (!attrs.equals(other.attrs))
            return false;
        if (eGgAlpha == null) {
            return other.eGgAlpha == null;
        } else return eGgAlpha.equals(other.eGgAlpha);
    }

}
