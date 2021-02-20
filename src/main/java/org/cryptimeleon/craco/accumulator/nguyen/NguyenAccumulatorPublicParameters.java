package org.cryptimeleon.craco.accumulator.nguyen;

import org.cryptimeleon.craco.accumulator.AccumulatorPublicParameters;
import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.hash.UniqueByteRepresentable;
import org.cryptimeleon.math.hash.annotations.AnnotatedUbrUtil;
import org.cryptimeleon.math.hash.annotations.UniqueByteRepresented;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearMap;
import org.cryptimeleon.math.structures.rings.zn.Zp;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public class NguyenAccumulatorPublicParameters implements AccumulatorPublicParameters, UniqueByteRepresentable {

    @Represented(restorer = "[foo]")
    List<NguyenAccumulatorIdentity> universe;

    @Represented
    private BigInteger p;

    @Represented
    private BilinearGroup bilinearGroup;

    @UniqueByteRepresented
    @Represented(restorer = "bilinearGroup::getG1")
    private GroupElement g;

    @UniqueByteRepresented
    @Represented(restorer = "bilinearGroup::getG2")
    private GroupElement g_Tilde;

    @UniqueByteRepresented
    @Represented(restorer = "bilinearGroup::getG2")
    private GroupElement g_Tilde_Power_S;

    @UniqueByteRepresented
    @Represented(restorer = "[bilinearGroup::getG1]")
    private GroupElement[] t;


    public NguyenAccumulatorPublicParameters(BigInteger p, BilinearGroup bilinearGroup, GroupElement g, GroupElement
            g_Tilde, GroupElement g_Tilde_Power_S, GroupElement[] t, List<NguyenAccumulatorIdentity> universe) {
        this.p = p;
        this.bilinearGroup = bilinearGroup;
        this.g = g;
        this.g_Tilde = g_Tilde;
        this.g_Tilde_Power_S = g_Tilde_Power_S;
        this.t = t;
        this.universe = universe;
    }

    public NguyenAccumulatorPublicParameters(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    @Override
    public BigInteger getUpperBoundForAccumulatableIdentities() {
        return BigInteger.valueOf(t.length - 1);
    }

    @Override
    public List<NguyenAccumulatorIdentity> getUniverse() {
        return universe;
    }

    public BigInteger getP() {
        return p;
    }

    public BilinearMap getBilinearMap() {
        return bilinearGroup.getBilinearMap();
    }

    public GroupElement getG() {
        return g;
    }

    public GroupElement getG_Tilde() {
        return g_Tilde;
    }

    public GroupElement getG_Tilde_Power_S() {
        return g_Tilde_Power_S;
    }

    public GroupElement[] getT() {
        return t;
    }

    public Zp getUniverseStructure() {
        return universe.get(0).getZp();
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        NguyenAccumulatorPublicParameters other = (NguyenAccumulatorPublicParameters) obj;
        return Objects.equals(universe, other.universe) &&
                Objects.equals(p, other.p) &&
                Objects.equals(bilinearGroup, other.bilinearGroup) &&
                Objects.equals(g, other.g) &&
                Objects.equals(g_Tilde, other.g_Tilde) &&
                Objects.equals(g_Tilde_Power_S, other.g_Tilde_Power_S) &&
                Arrays.equals(t, other.t);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(universe, p, bilinearGroup, g, g_Tilde, g_Tilde_Power_S);
        result = 31 * result + Arrays.hashCode(t);
        return result;
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }
}
