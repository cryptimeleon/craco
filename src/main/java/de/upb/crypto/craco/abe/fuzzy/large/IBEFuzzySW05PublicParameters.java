package de.upb.crypto.craco.abe.fuzzy.large;

import de.upb.crypto.craco.interfaces.PublicParameters;
import de.upb.crypto.math.interfaces.hash.HashIntoStructure;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

import java.math.BigInteger;

/**
 * The public parameters for the {@link IBEFuzzySW05} generated in
 * the {@link IBEFuzzySW05Setup}.
 *
 * @author Mirko Jürgens, refactoring: Denis Diemert
 */
public class IBEFuzzySW05PublicParameters implements PublicParameters {

    /**
     * universe size n
     */
    @Represented
    private BigInteger n;

    /**
     * identity threshold d
     */
    @Represented
    private BigInteger identityThresholdD;

    /**
     * generator g \in G_1
     */
    @Represented(structure = "groupG1", recoveryMethod = GroupElement.RECOVERY_METHOD)
    private GroupElement g;

    /**
     * generator g1 \in G_1
     */
    @Represented(structure = "groupG1", recoveryMethod = GroupElement.RECOVERY_METHOD)
    private GroupElement g1;

    /**
     * generator g2 \in G_1
     */
    @Represented(structure = "groupG1", recoveryMethod = GroupElement.RECOVERY_METHOD)
    private GroupElement g2;

    @Represented
    private HashIntoStructure hashToG1;

    @Represented
    private Group groupG1;

    @Represented
    private Group groupGT;

    @Represented
    private BilinearMap e;

    public IBEFuzzySW05PublicParameters(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    public IBEFuzzySW05PublicParameters() {
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public BigInteger getN() {
        return n;
    }

    public void setN(BigInteger n) {
        this.n = n;
    }

    public BigInteger getIdentityThresholdD() {
        return identityThresholdD;
    }

    public void setIdentityThresholdD(BigInteger identityThresholdD) {
        this.identityThresholdD = identityThresholdD;
    }

    public GroupElement getG() {
        return g;
    }

    public void setG(GroupElement g) {
        this.g = g;
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
        result = prime * result + ((identityThresholdD == null) ? 0 : identityThresholdD.hashCode());
        result = prime * result + ((g == null) ? 0 : g.hashCode());
        result = prime * result + ((g1 == null) ? 0 : g1.hashCode());
        result = prime * result + ((g2 == null) ? 0 : g2.hashCode());
        result = prime * result + ((groupG1 == null) ? 0 : groupG1.hashCode());
        result = prime * result + ((groupGT == null) ? 0 : groupGT.hashCode());
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
        IBEFuzzySW05PublicParameters other = (IBEFuzzySW05PublicParameters) obj;
        if (e == null) {
            if (other.e != null)
                return false;
        } else if (!e.equals(other.e))
            return false;
        if (identityThresholdD == null) {
            if (other.identityThresholdD != null)
                return false;
        } else if (!identityThresholdD.equals(other.identityThresholdD))
            return false;
        if (g == null) {
            if (other.g != null)
                return false;
        } else if (!g.equals(other.g))
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

    public HashIntoStructure getHashToG1() {
        return hashToG1;
    }

    public void setHashToG1(HashIntoStructure hashToG1) {
        this.hashToG1 = hashToG1;
    }
}
