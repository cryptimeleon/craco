package de.upb.crypto.craco.abe.ibe;

import de.upb.crypto.craco.interfaces.PublicParameters;
import de.upb.crypto.math.factory.BilinearGroup;
import de.upb.crypto.math.interfaces.hash.HashIntoStructure;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

import java.math.BigInteger;
import java.util.Objects;

/**
 * The public parameters for the {@link FullIdent} generated in the
 * {@link FullIdentSetup}.
 *
 * @author Mirko Jürgens
 */
public class FullIdentPublicParameters implements PublicParameters {

    @Represented
    private BilinearGroup bilinearGroup; // G1 x G1 -> G2

    @Represented(restorer = "bilinearGroup::getG1")
    private GroupElement p; // Generator of G_1

    @Represented(restorer = "bilinearGroup::getG1")
    private GroupElement p_pub; // s * p

    @Represented
    private BigInteger n; // length of the plain-texts

    @Represented
    private HashIntoStructure hashToG1;

    public FullIdentPublicParameters() {

    }

    public FullIdentPublicParameters(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public Group getGroupG1() {
        return bilinearGroup.getG1();
    }

    public Group getGroupG2() {
        return bilinearGroup.getG2();
    }

    public BilinearMap getBilinearMap() {
        return bilinearGroup.getBilinearMap();
    }

    public void setBilinearGroup(BilinearGroup bilinearGroup) {
        this.bilinearGroup = bilinearGroup;
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
        return Objects.hash(bilinearGroup, p, p_pub, n, hashToG1);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj== null || getClass() != obj.getClass())
            return false;
        FullIdentPublicParameters other = (FullIdentPublicParameters) obj;
        return Objects.equals(bilinearGroup, other.bilinearGroup)
                && Objects.equals(p, other.p)
                && Objects.equals(p_pub, other.p_pub)
                && Objects.equals(n, other.n)
                && Objects.equals(hashToG1, other.hashToG1);

    }

    public HashIntoStructure getHashToG1() {
        return hashToG1;
    }

    public void setHashToG1(HashIntoStructure hashToG1) {
        this.hashToG1 = hashToG1;
    }
}