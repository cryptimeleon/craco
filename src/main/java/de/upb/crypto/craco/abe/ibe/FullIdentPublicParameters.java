package de.upb.crypto.craco.abe.ibe;

import de.upb.crypto.craco.common.interfaces.PublicParameters;
import de.upb.crypto.math.interfaces.hash.HashIntoStructure;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.math.BigInteger;

/**
 * The public parameters for the {@link FullIdent} generated in the
 * {@link FullIdentSetup}.
 *
 * @author Mirko Jürgens
 */
public class FullIdentPublicParameters implements PublicParameters {

    @Represented
    private Group groupG1, groupG2;

    @Represented
    private BilinearMap e; // G1 x G1 -> G2

    @Represented(structure = "groupG1", recoveryMethod = GroupElement.RECOVERY_METHOD)
    private GroupElement p; // Generator of G_1

    @Represented(structure = "groupG1", recoveryMethod = GroupElement.RECOVERY_METHOD)
    private GroupElement p_pub; // s * p

    @Represented
    private BigInteger n; // length of the plain-texts

    @Represented
    private HashIntoStructure hashToG1;

    public FullIdentPublicParameters() {

    }

    public FullIdentPublicParameters(Representation repr) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(repr, this);

    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
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

    public BilinearMap getE() {
        return e;
    }

    public void setE(BilinearMap e) {
        this.e = e;
    }

    public GroupElement getP() {
        return p;
    }

    public void setP(GroupElement p) {
        this.p = p;
    }

    public GroupElement getP_pub() {
        return p_pub;
    }

    public void setP_pub(GroupElement p_pub) {
        this.p_pub = p_pub;
    }

    public BigInteger getN() {
        return n;
    }

    public void setN(BigInteger n) {
        this.n = n;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((p == null) ? 0 : p.hashCode());
        result = prime * result + ((p_pub == null) ? 0 : p_pub.hashCode());
        result = prime * result + ((e == null) ? 0 : e.hashCode());
        result = prime * result + ((groupG1 == null) ? 0 : groupG1.hashCode());
        result = prime * result + ((groupG2 == null) ? 0 : groupG2.hashCode());
        result = prime * result + ((hashToG1 == null) ? 0 : hashToG1.hashCode());
        result = prime * result + ((n == null) ? 0 : n.hashCode());
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
        FullIdentPublicParameters other = (FullIdentPublicParameters) obj;
        if (p == null) {
            if (other.p != null)
                return false;
        } else if (!p.equals(other.p))
            return false;
        if (p_pub == null) {
            if (other.p_pub != null)
                return false;
        } else if (!p_pub.equals(other.p_pub))
            return false;
        if (e == null) {
            if (other.e != null)
                return false;
        } else if (!e.equals(other.e))
            return false;
        if (groupG1 == null) {
            if (other.groupG1 != null)
                return false;
        } else if (!groupG1.equals(other.groupG1))
            return false;
        if (groupG2 == null) {
            if (other.groupG2 != null)
                return false;
        } else if (!groupG2.equals(other.groupG2))
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

    public HashIntoStructure getHashToG1() {
        return hashToG1;
    }

    public void setHashToG1(HashIntoStructure hashToG1) {
        this.hashToG1 = hashToG1;
    }
}