package de.upb.crypto.craco.abe.cp.small;

import de.upb.crypto.craco.interfaces.PublicParameters;
import de.upb.crypto.craco.interfaces.abe.Attribute;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

import java.util.Collections;
import java.util.Map;

/**
 * The public parameters for the {@link ABECPWat11Small}, generated in
 * the {@link ABECPWat11SmallSetup}.
 *
 * @author Mirko Jürgens
 */
public class ABECPWat11SmallPublicParameters implements PublicParameters {

    @Represented
    public Group groupG1, groupGT;

    @Represented
    private BilinearMap e;

    @Represented(restorer = "groupG1")
    private GroupElement g; // Generator of G_1

    @Represented(restorer = "groupGT")
    private GroupElement eGGAlpha; // in G_T

    @Represented(restorer = "groupG1")
    private GroupElement gA; // in G_1

    @Represented(restorer = "foo -> groupG1")
    private Map<Attribute, GroupElement> h; // Attribute in Universe, Element in
    // G_1

    public ABECPWat11SmallPublicParameters() {
    }

    public ABECPWat11SmallPublicParameters(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    public Group getGroupG1() {
        return groupG1;
    }

    public void setGroupG1(Group groupG1) {
        this.groupG1 = groupG1;
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

    public GroupElement getG() {
        return g;
    }

    public void setG(GroupElement g) {
        this.g = g;
    }

    public GroupElement geteGGAlpha() {
        return eGGAlpha;
    }

    public void seteGGAlpha(GroupElement eGGAlpha) {
        this.eGGAlpha = eGGAlpha;
    }

    public GroupElement getgA() {
        return gA;
    }

    public void setgA(GroupElement gA) {
        this.gA = gA;
    }

    public Map<Attribute, GroupElement> getH() {
        return h;
    }

    public void setH(Map<Attribute, GroupElement> h) {
        this.h = Collections.unmodifiableMap(h);
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
        result = prime * result + ((g == null) ? 0 : g.hashCode());
        result = prime * result + ((gA == null) ? 0 : gA.hashCode());
        result = prime * result + ((groupG1 == null) ? 0 : groupG1.hashCode());
        result = prime * result + ((groupGT == null) ? 0 : groupGT.hashCode());
        result = prime * result + ((h == null) ? 0 : h.hashCode());
        result = prime * result + ((eGGAlpha == null) ? 0 : eGGAlpha.hashCode());
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
        ABECPWat11SmallPublicParameters other = (ABECPWat11SmallPublicParameters) obj;
        if (e == null) {
            if (other.e != null)
                return false;
        } else if (!e.equals(other.e))
            return false;
        if (g == null) {
            if (other.g != null)
                return false;
        } else if (!g.equals(other.g))
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
        if (h == null) {
            if (other.h != null)
                return false;
        } else if (!h.equals(other.h))
            return false;
        if (eGGAlpha == null) {
            if (other.eGGAlpha != null)
                return false;
        } else if (!eGGAlpha.equals(other.eGGAlpha))
            return false;
        return true;
    }

}
