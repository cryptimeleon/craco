package de.upb.crypto.craco.accumulators.nguyen;

import de.upb.crypto.craco.accumulators.interfaces.AccumulatorPublicParameters;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.hash.ByteAccumulator;
import de.upb.crypto.math.hash.UniqueByteRepresentable;
import de.upb.crypto.math.structures.groups.GroupElement;
import de.upb.crypto.math.structures.groups.elliptic.BilinearGroup;
import de.upb.crypto.math.structures.groups.elliptic.BilinearMap;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.ReprUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.rings.zn.Zp;

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
