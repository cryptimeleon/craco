package de.upb.crypto.craco.abe.cp.small;

import de.upb.crypto.craco.interfaces.PublicParameters;
import de.upb.crypto.craco.interfaces.abe.Attribute;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedMap;

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
    private Group groupG1, groupGT;

    @Represented
    private BilinearMap e;

    @Represented(structure = "groupG1", recoveryMethod = GroupElement.RECOVERY_METHOD)
    private GroupElement g; // Generator of G_1

    @Represented(structure = "groupGT", recoveryMethod = GroupElement.RECOVERY_METHOD)
    private GroupElement y; // in G_T

    @Represented(structure = "groupG1", recoveryMethod = GroupElement.RECOVERY_METHOD)
    private GroupElement g_a; // in G_1

    @RepresentedMap(keyRestorer = @Represented, valueRestorer = @Represented(structure = "groupG1", recoveryMethod =
            GroupElement.RECOVERY_METHOD))
    private Map<Attribute, GroupElement> t; // Attribute in Universe, Element in
    // G_1

    public ABECPWat11SmallPublicParameters() {
    }

    public ABECPWat11SmallPublicParameters(Representation repr) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(repr, this);
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

    public GroupElement getY() {
        return y;
    }

    public void setY(GroupElement y) {
        this.y = y;
    }

    public GroupElement getG_a() {
        return g_a;
    }

    public void setG_a(GroupElement g_a) {
        this.g_a = g_a;
    }

    public Map<Attribute, GroupElement> getT() {
        return t;
    }

    public void setT(Map<Attribute, GroupElement> t) {
        this.t = Collections.unmodifiableMap(t);
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((e == null) ? 0 : e.hashCode());
        result = prime * result + ((g == null) ? 0 : g.hashCode());
        result = prime * result + ((g_a == null) ? 0 : g_a.hashCode());
        result = prime * result + ((groupG1 == null) ? 0 : groupG1.hashCode());
        result = prime * result + ((groupGT == null) ? 0 : groupGT.hashCode());
        result = prime * result + ((t == null) ? 0 : t.hashCode());
        result = prime * result + ((y == null) ? 0 : y.hashCode());
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
        if (g_a == null) {
            if (other.g_a != null)
                return false;
        } else if (!g_a.equals(other.g_a))
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
        if (t == null) {
            if (other.t != null)
                return false;
        } else if (!t.equals(other.t))
            return false;
        if (y == null) {
            if (other.y != null)
                return false;
        } else if (!y.equals(other.y))
            return false;
        return true;
    }

}
