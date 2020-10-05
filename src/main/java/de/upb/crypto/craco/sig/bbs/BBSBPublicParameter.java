package de.upb.crypto.craco.sig.bbs;

import de.upb.crypto.craco.interfaces.PublicParameters;
import de.upb.crypto.math.factory.BilinearGroup;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.mappings.GroupHomomorphism;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;
import de.upb.crypto.math.serialization.util.RepresentationUtil;
import de.upb.crypto.math.structures.zn.HashIntoZn;
import de.upb.crypto.math.structures.zn.HashIntoZp;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;
import java.util.Objects;

public class BBSBPublicParameter implements PublicParameters {
    @Represented
    private BilinearGroup bilinearGroup; // G1 x G2 -> GT
    @Represented
    private HashIntoZn hashIntoZp;
    @Represented(restorer = "bilinearGroup::getG1")
    private GroupElement g1; // in G1
    @Represented(restorer = "bilinearGroup::getG2")
    private GroupElement g2; // in G2

    public BBSBPublicParameter(BilinearGroup bilinearGroup, HashIntoZn hashIntoZp) {
        this.bilinearGroup = bilinearGroup;
        this.hashIntoZp = hashIntoZp;
    }

    public BBSBPublicParameter(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public BilinearGroup getBilinearGroup() {
        return bilinearGroup;
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

    /**
     * Returns the group Zp (where p is the group order of G1, G2, and GT)
     */
    public Zp getZp() {
        return new Zp(bilinearGroup.getZn().size());
    }

    /**
     * Returns the group size of G1,G2, and GT
     */
    public BigInteger getGroupSize() {
        return getZp().size();
    }

    public HashIntoZn getHashIntoZp() {
        return hashIntoZp;
    }

    @Override
    public int hashCode() {
        return Objects.hash(bilinearGroup, hashIntoZp, g1, g2);
    }

    @Override
    public boolean equals(Object other) {
        if (this == other)
            return true;
        if (other == null || getClass() != other.getClass())
            return false;
        BBSBPublicParameter that = (BBSBPublicParameter) other;
        return Objects.equals(bilinearGroup, that.bilinearGroup)
                && Objects.equals(hashIntoZp, that.hashIntoZp)
                && Objects.equals(g1, that.g1)
                && Objects.equals(g2, that.g2);
    }

    public GroupHomomorphism getGroupHom() {
        return bilinearGroup.getHomomorphismG2toG1();
    }

    public BilinearMap getBilinearMap() {
        return bilinearGroup.getBilinearMap();
    }

    public Group getGroupG1() {
        return bilinearGroup.getG1();
    }

    public Group getGroupG2() {
        return bilinearGroup.getG2();
    }
}
