package de.upb.crypto.craco.abe.cp.large;

import de.upb.crypto.craco.common.interfaces.PublicParameters;
import de.upb.crypto.math.structures.HashIntoStructure;
import de.upb.crypto.math.structures.groups.Group;
import de.upb.crypto.math.structures.groups.GroupElement;
import de.upb.crypto.math.structures.groups.elliptic.BilinearGroup;
import de.upb.crypto.math.structures.groups.elliptic.BilinearMap;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.ReprUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.Objects;

/**
 * The public parameters for the {@link ABECPWat11}, generated in
 * the {@link ABECPWat11Setup}.
 *
 * @author Mirko Jürgens, Jan Bobolz
 */
public class ABECPWat11PublicParameters implements PublicParameters {

    @Represented
    protected BilinearGroup bilinearGroup;

    @Represented(restorer = "bilinearGroup::getG1")
    protected GroupElement g; // Generator of G_1

    @Represented(restorer = "bilinearGroup::getGT")
    protected GroupElement y; // in G_T

    @Represented(restorer = "bilinearGroup::getG1")
    protected GroupElement gA; // in G_1

    @Represented
    protected HashIntoStructure hashToG1;

    @Represented
    protected Integer lMax;

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

    public GroupElement getgA() {
        return gA;
    }

    public void setgA(GroupElement gA) {
        this.gA = gA;
    }

    public int getlMax() {
        return lMax;
    }

    public void setlMax(int lMax) {
        this.lMax = lMax;
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
        return Objects.hash(bilinearGroup, g, y, gA, hashToG1, lMax, n);
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
        return Objects.equals(bilinearGroup, other.bilinearGroup)
                && Objects.equals(g, other.g)
                && Objects.equals(y, other.y)
                && Objects.equals(gA, other.gA)
                && Objects.equals(hashToG1, other.hashToG1)
                && Objects.equals(lMax, other.lMax)
                && Objects.equals(n, other.n);
    }
}
