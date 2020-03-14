package de.upb.crypto.craco.accumulators.nguyen;

import de.upb.crypto.craco.accumulators.interfaces.AccumulatorPublicParameters;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public class NguyenAccumulatorPublicParameters implements AccumulatorPublicParameters, UniqueByteRepresentable {

    @Represented(restorer = "[foo]")
    List<NguyenAccumulatorIdentity> universe;
    // for Representation purposes
    @Represented
    Group g1;

    @Represented
    Group g2;

    @Represented
    private BigInteger p;

    @Represented
    private BilinearMap bilinearMap;

    @UniqueByteRepresented
    @Represented(restorer = "g1")
    private GroupElement g;

    @UniqueByteRepresented
    @Represented(restorer = "g2")
    private GroupElement g_Tilde;

    @UniqueByteRepresented
    @Represented(restorer = "g2")
    private GroupElement g_Tilde_Power_S;

    @UniqueByteRepresented
    @Represented(restorer = "[g1]")
    private GroupElement[] t;


    public NguyenAccumulatorPublicParameters(BigInteger p, BilinearMap bilinearMap, GroupElement g, GroupElement
            g_Tilde, GroupElement g_Tilde_Power_S, GroupElement[] t, List<NguyenAccumulatorIdentity> universe) {
        this.p = p;
        this.bilinearMap = bilinearMap;
        this.g = g;
        this.g_Tilde = g_Tilde;
        this.g_Tilde_Power_S = g_Tilde_Power_S;
        this.t = t;
        this.universe = universe;
        this.g1 = bilinearMap.getG1();
        this.g2 = bilinearMap.getG2();
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
        return bilinearMap;
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
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        NguyenAccumulatorPublicParameters that = (NguyenAccumulatorPublicParameters) o;
        return Objects.equals(universe, that.universe) &&
                Objects.equals(g1, that.g1) &&
                Objects.equals(g2, that.g2) &&
                Objects.equals(p, that.p) &&
                Objects.equals(bilinearMap, that.bilinearMap) &&
                Objects.equals(g, that.g) &&
                Objects.equals(g_Tilde, that.g_Tilde) &&
                Objects.equals(g_Tilde_Power_S, that.g_Tilde_Power_S) &&
                Arrays.equals(t, that.t);
    }

    @Override
    public int hashCode() {

        int result = Objects.hash(universe, g1, g2, p, bilinearMap, g, g_Tilde, g_Tilde_Power_S);
        result = 31 * result + Arrays.hashCode(t);
        return result;
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }
}
