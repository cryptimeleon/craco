package de.upb.crypto.craco.abe.kp.large;

import de.upb.crypto.craco.interfaces.PublicParameters;
import de.upb.crypto.math.interfaces.hash.HashIntoStructure;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedMap;

import java.math.BigInteger;
import java.util.Map;

/**
 * The public parameters for the {@link ABEKPGPSW06}, generated in
 * the {@link ABEKPGPSW06Setup}.
 *
 * @author Mirko Jürgens
 */
public class ABEKPGPSW06PublicParameters implements PublicParameters {

    @Represented(restorer = "groupG1")
    private GroupElement g1_generator;

    // T_i in groupG1
    @Represented(restorer = "foo -> groupG1")
    private Map<BigInteger, GroupElement> t;

    // in groupGT
    @Represented(restorer = "groupGT")
    private GroupElement y;

    @Represented
    private Group groupG1, groupG2, groupGT;

    @Represented
    private BilinearMap e;

    @Represented
    private BigInteger n;

    @Represented
    private HashIntoStructure hashToG1;

    public ABEKPGPSW06PublicParameters() {
    }

    public ABEKPGPSW06PublicParameters(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public GroupElement getG1_generator() {
        return g1_generator;
    }

    public void setG1_generator(GroupElement g) {
        this.g1_generator = g;
    }

    public Map<BigInteger, GroupElement> getT() {
        return t;
    }

    public void setT(Map<BigInteger, GroupElement> t) {
        this.t = t;
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
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        ABEKPGPSW06PublicParameters other = (ABEKPGPSW06PublicParameters) obj;
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
        if (e == null) {
            if (other.e != null)
                return false;
        } else if (!e.equals(other.e))
            return false;
        if (g1_generator == null) {
            if (other.g1_generator != null)
                return false;
        } else if (!g1_generator.equals(other.g1_generator))
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
        if (hashToG1 == null) {
            if (other.hashToG1 != null)
                return false;
        } else if (!hashToG1.equals(other.hashToG1))
            return false;
        if (n == null) {
            if (other.n != null)
                return false;
        } else if (!n.equals(other.n))
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((t == null) ? 0 : t.hashCode());
        result = prime * result + ((y == null) ? 0 : y.hashCode());
        result = prime * result + ((e == null) ? 0 : e.hashCode());
        result = prime * result + ((g1_generator == null) ? 0 : g1_generator.hashCode());
        result = prime * result + ((groupG1 == null) ? 0 : groupG1.hashCode());
        result = prime * result + ((groupGT == null) ? 0 : groupGT.hashCode());
        result = prime * result + ((hashToG1 == null) ? 0 : hashToG1.hashCode());
        result = prime * result + ((n == null) ? 0 : n.hashCode());
        return result;
    }

    public BigInteger getN() {
        return n;
    }

    public void setN(BigInteger n) {
        this.n = n;
    }

    public HashIntoStructure getHashToG1() {
        return hashToG1;
    }

    public void setHashToG1(HashIntoStructure hashToG1) {
        this.hashToG1 = hashToG1;
    }

    public Group getGroupG2() {
        return groupG2;
    }

    public void setGroupG2(Group groupG2) {
        this.groupG2 = groupG2;
    }
}
