package de.upb.crypto.craco.common;

import de.upb.crypto.craco.common.utils.LagrangeUtil;
import de.upb.crypto.math.hash.impl.ByteArrayAccumulator;
import de.upb.crypto.math.hash.ByteAccumulator;
import de.upb.crypto.math.hash.UniqueByteRepresentable;
import de.upb.crypto.math.structures.groups.Group;
import de.upb.crypto.math.structures.groups.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.ReprUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.groups.HashIntoGroup;
import de.upb.crypto.math.structures.rings.zn.HashIntoZn;
import de.upb.crypto.math.structures.rings.zn.Zp;
import de.upb.crypto.math.structures.rings.zn.Zp.ZpElement;

import java.math.BigInteger;
import java.util.*;
/**
 * A hash function allowing hashing into a specific group.
 */
public class WatersHash implements HashIntoGroup {
    @Represented
    private Group g;
    @Represented(restorer = "[g]")
    protected List<GroupElement> T;

    public WatersHash(Group g, int n) {
        T = new ArrayList<>();
        this.g = g;
        for (int i = 1; i <= n; i++) {
            T.add(g.getUniformlyRandomNonNeutral().compute());
        }
    }

    public WatersHash(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public GroupElement hash(byte[] x) {
        GroupElement result = g.getNeutralElement();
        Set<BigInteger> N = new HashSet<>();
        for (int i = 1; i <= T.size(); i++) {
            N.add(BigInteger.valueOf(i));
        }
        HashIntoZn baseHash = new HashIntoZn(g.size());
        for (int i = 1; i <= T.size(); i++) {
            ZpElement lg = LagrangeUtil.computeCoefficient(Zp.valueOf(i, g.size()),
                    N,
                    Zp.valueOf(baseHash.hash(x).getInteger(), baseHash.getTargetStructure().size())
            );
            result = result.op(T.get(i - 1).pow(lg));
        }

        return result;
    }

    public List<GroupElement> getT() {
        return T;
    }

    public Group getG() {
        return g;
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(T);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        WatersHash other = (WatersHash) obj;
        return Objects.equals(T, other.T);
    }

    @Override
    public GroupElement hash(UniqueByteRepresentable ubr) {
        ByteAccumulator acc = new ByteArrayAccumulator();
        acc = ubr.updateAccumulator(acc);
        return hash(acc.extractBytes());
    }
}
