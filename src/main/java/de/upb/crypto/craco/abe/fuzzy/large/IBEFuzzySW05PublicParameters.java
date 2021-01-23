package de.upb.crypto.craco.abe.fuzzy.large;

import de.upb.crypto.craco.common.interfaces.PublicParameters;
import de.upb.crypto.math.structures.groups.Group;
import de.upb.crypto.math.structures.groups.GroupElement;
import de.upb.crypto.math.structures.groups.HashIntoGroup;
import de.upb.crypto.math.structures.groups.elliptic.BilinearGroup;
import de.upb.crypto.math.structures.groups.elliptic.BilinearMap;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.ReprUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.math.BigInteger;
import java.util.Objects;

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
    @Represented(restorer = "bilinearGroup::getG1")
    private GroupElement g;

    /**
     * generator g1 \in G_1
     */
    @Represented(restorer = "bilinearGroup::getG1")
    private GroupElement g1;

    /**
     * generator g2 \in G_1
     */
    @Represented(restorer = "bilinearGroup::getG1")
    private GroupElement g2;

    @Represented
    private HashIntoGroup hashToG1;

    @Represented
    private BilinearGroup bilinearGroup;

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
        return bilinearGroup.getG1();
    }

    public Group getGroupGT() {
        return bilinearGroup.getGT();
    }

    public BilinearMap getE() {
        return bilinearGroup.getBilinearMap();
    }

    public void setBilinearGroup(BilinearGroup bilGroup) {
        this.bilinearGroup = bilGroup;
    }

    @Override
    public int hashCode() {
        return Objects.hash(n, identityThresholdD, g, g1, g2, hashToG1, bilinearGroup);
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
        return Objects.equals(n, other.n)
                && Objects.equals(g, other.g)
                && Objects.equals(g1, other.g1)
                && Objects.equals(g2, other.g2)
                && Objects.equals(hashToG1, other.hashToG1)
                && Objects.equals(bilinearGroup, other.bilinearGroup);
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

    public HashIntoGroup getHashToG1() {
        return hashToG1;
    }

    public void setHashToG1(HashIntoGroup hashToG1) {
        this.hashToG1 = hashToG1;
    }
}
