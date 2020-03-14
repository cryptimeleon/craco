package de.upb.crypto.craco.abe.cp.large;

import de.upb.crypto.craco.interfaces.PublicParameters;
import de.upb.crypto.math.interfaces.hash.HashIntoStructure;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

/**
 * The public parameters for the {@link ABECPWat11}, generated in
 * the {@link ABECPWat11Setup}.
 *
 * @author Mirko Jürgens, Jan Bobolz
 */
public class ABECPWat11PublicParameters implements PublicParameters {

    @Represented
    protected Group groupG1, groupGT;

    @Represented
    protected BilinearMap e;

    @Represented(restorer = "groupG1")
    protected GroupElement g; // Generator of G_1

    @Represented(restorer = "groupGT")
    protected GroupElement y; // in G_T

    @Represented(restorer = "groupG1")
    protected GroupElement g_a; // in G_1

    @Represented
    protected HashIntoStructure hashToG1;

    @Represented
    protected Integer l_max;

    @Represented
    protected Integer n;

    public ABECPWat11PublicParameters() {
    }

    public ABECPWat11PublicParameters(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    public HashIntoStructure getHashToG1() {
        return hashToG1;
    }

    public void setHashToG1(HashIntoStructure h) {
        hashToG1 = h;
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

    public int getL_max() {
        return l_max;
    }

    public void setL_max(int l_max) {
        this.l_max = l_max;
    }

    public int getN() {
        return n;
    }

    public void setN(int n) {
        this.n = n;
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((hashToG1 == null) ? 0 : hashToG1.hashCode());
        result = prime * result + ((y == null) ? 0 : y.hashCode());
        result = prime * result + ((e == null) ? 0 : e.hashCode());
        result = prime * result + ((g == null) ? 0 : g.hashCode());
        result = prime * result + ((g_a == null) ? 0 : g_a.hashCode());
        result = prime * result + ((groupG1 == null) ? 0 : groupG1.hashCode());
        result = prime * result + ((groupGT == null) ? 0 : groupGT.hashCode());
        result = prime * result + l_max;
        result = prime * result + n;
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
        ABECPWat11PublicParameters other = (ABECPWat11PublicParameters) obj;
        if (hashToG1 == null) {
            if (other.hashToG1 != null)
                return false;
        } else if (!hashToG1.equals(other.hashToG1))
            return false;
        if (y == null) {
            if (other.y != null)
                return false;
        } else if (!y.equals(other.y))
            return false;
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
        if (l_max != other.l_max)
            return false;
        if (n != other.n)
            return false;
        return true;
    }
}
