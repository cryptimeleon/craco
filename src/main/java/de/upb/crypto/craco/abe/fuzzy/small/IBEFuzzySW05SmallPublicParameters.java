package de.upb.crypto.craco.abe.fuzzy.small;

import de.upb.crypto.craco.interfaces.PublicParameters;
import de.upb.crypto.craco.interfaces.abe.Attribute;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedMap;

import java.math.BigInteger;
import java.util.Collections;
import java.util.Map;

/**
 * The public parameters for the {@link IBEFuzzySW05Small} generated in
 * the {@link IBEFuzzySW05SmallSetup}.
 *
 * @author Mirko Jürgens
 */
public class IBEFuzzySW05SmallPublicParameters implements PublicParameters {

    @Represented
    private BigInteger d; // identity threshold

    @Represented(structure = "groupG1", recoveryMethod = GroupElement.RECOVERY_METHOD)
    private GroupElement g; // in G_1

    @RepresentedMap(keyRestorer = @Represented, valueRestorer = @Represented(structure = "groupG1", recoveryMethod =
            GroupElement.RECOVERY_METHOD))
    private Map<Attribute, GroupElement> T; // in G_1

    @Represented(structure = "groupGT", recoveryMethod = GroupElement.RECOVERY_METHOD)
    private GroupElement y; // in G_T

    @Represented
    private Group groupG1;

    @Represented
    private Group groupGT;

    @Represented
    private BilinearMap e;

    public IBEFuzzySW05SmallPublicParameters(Representation repr) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(repr, this);
    }

    public IBEFuzzySW05SmallPublicParameters() {
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    public BigInteger getD() {
        return d;
    }

    public void setD(BigInteger d) {
        this.d = d;
    }

    public GroupElement getG() {
        return g;
    }

    public void setG(GroupElement g) {
        this.g = g;
    }

    public Map<Attribute, GroupElement> getT() {
        return T;
    }

    public void setT(Map<Attribute, GroupElement> t2) {
        T = Collections.unmodifiableMap(t2);
    }

    public GroupElement getY() {
        return y;
    }

    public void setY(GroupElement y) {
        this.y = y;
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

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((e == null) ? 0 : e.hashCode());
        result = prime * result + ((T == null) ? 0 : T.hashCode());
        result = prime * result + ((y == null) ? 0 : y.hashCode());
        result = prime * result + ((d == null) ? 0 : d.hashCode());
        result = prime * result + ((g == null) ? 0 : g.hashCode());
        result = prime * result + ((groupG1 == null) ? 0 : groupG1.hashCode());
        result = prime * result + ((groupGT == null) ? 0 : groupGT.hashCode());
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
        IBEFuzzySW05SmallPublicParameters other = (IBEFuzzySW05SmallPublicParameters) obj;
        if (e == null) {
            if (other.e != null)
                return false;
        } else if (!e.equals(other.e))
            return false;
        if (T == null) {
            if (other.T != null)
                return false;
        } else if (!T.keySet().containsAll(other.T.keySet()) || !other.T.keySet().containsAll(T.keySet()))
            return false;
        if (y == null) {
            if (other.y != null)
                return false;
        } else if (!y.equals(other.y))
            return false;
        if (d == null) {
            if (other.d != null)
                return false;
        } else if (!d.equals(other.d))
            return false;
        if (g == null) {
            if (other.g != null)
                return false;
        } else if (!g.equals(other.g))
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
        return true;
    }
}
