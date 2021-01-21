package de.upb.crypto.craco.abe.kp.large;

import de.upb.crypto.craco.common.interfaces.PublicParameters;
import de.upb.crypto.math.interfaces.hash.HashIntoGroup;
import de.upb.crypto.math.interfaces.hash.HashIntoStructure;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.pairings.generic.BilinearGroup;
import de.upb.crypto.math.pairings.generic.BilinearMap;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

import java.math.BigInteger;
import java.util.Map;
import java.util.Objects;

/**
 * The public parameters for the {@link ABEKPGPSW06}, generated in
 * the {@link ABEKPGPSW06Setup}.
 *
 *
 */
public class ABEKPGPSW06PublicParameters implements PublicParameters {

    @Represented(restorer = "bilinearGroup::getG1")
    private GroupElement g1Generator;

    // T_i in groupG1
    @Represented(restorer = "foo -> bilinearGroup::getG1")
    private Map<BigInteger, GroupElement> t;

    // in groupGT
    @Represented(restorer = "bilinearGroup::getGT")
    private GroupElement y;

    @Represented
    private BilinearGroup bilinearGroup;

    @Represented
    private BigInteger n;

    @Represented
    private HashIntoGroup hashToG1;

    public ABEKPGPSW06PublicParameters() {
    }

    public ABEKPGPSW06PublicParameters(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public GroupElement getG1Generator() {
        return g1Generator;
    }

    public void setG1Generator(GroupElement g) {
        this.g1Generator = g;
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
        return bilinearGroup.getG1();
    }

    public Group getGroupGT() {
        return bilinearGroup.getGT();
    }

    public BilinearMap getBilinearMap() {
        return bilinearGroup.getBilinearMap();
    }

    public void setBilinearGroup(BilinearGroup bilinearGroup) {
        this.bilinearGroup = bilinearGroup;
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
        return Objects.equals(g1Generator, other.g1Generator)
                && Objects.equals(t, other.t)
                && Objects.equals(y, other.y)
                && Objects.equals(bilinearGroup, other.bilinearGroup)
                && Objects.equals(n, other.n)
                && Objects.equals(hashToG1, other.hashToG1);
    }

    @Override
    public int hashCode() {
        return Objects.hash(g1Generator, t, y, bilinearGroup, n, hashToG1);
    }

    public BigInteger getN() {
        return n;
    }

    public void setN(BigInteger n) {
        this.n = n;
    }

    public HashIntoGroup getHashToG1() {
        return hashToG1;
    }

    public void setHashToG1(HashIntoGroup hashToG1) {
        this.hashToG1 = hashToG1;
    }

    public Group getGroupG2() {
        return bilinearGroup.getG2();
    }
}
