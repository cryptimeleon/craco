package de.upb.crypto.craco.common;

import de.upb.crypto.craco.common.utils.LagrangeUtil;
import de.upb.crypto.math.hash.impl.ByteArrayAccumulator;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.hash.HashIntoStructure;
import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;
import de.upb.crypto.math.interfaces.structures.Element;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.ListRepresentation;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.RepresentableRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.HashIntoZn;
import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class WatersHash implements HashIntoStructure {
    private Group g;

    protected List<GroupElement> T;

    public WatersHash(Group g, int n) {
        T = new ArrayList<>();
        this.g = g;
        for (int i = 1; i <= n; i++) {
            T.add(g.getUniformlyRandomNonNeutral());
        }
    }

    public WatersHash(Representation repr) {
        g = (Group) repr.obj().get("g").repr().recreateRepresentable();
        T = new ArrayList<>();
        repr.obj().get("T").list().forEach(t -> T.add(g.getElement(t)));
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation repr = new ObjectRepresentation();
        repr.put("g", new RepresentableRepresentation(g));
        ListRepresentation tRepr =
                new ListRepresentation(T.stream().map(GroupElement::getRepresentation).collect(Collectors.toList()));
        repr.put("T", tRepr);

        return repr;
    }

    @Override
    public Element hashIntoStructure(byte[] x) {
        GroupElement result = g.getNeutralElement();
        Set<BigInteger> N = new HashSet<>();
        for (int i = 1; i <= T.size(); i++) {
            N.add(BigInteger.valueOf(i));
        }
        HashIntoZn baseHash = new HashIntoZn(g.size());
        for (int i = 1; i <= T.size(); i++) {
            ZpElement lg = LagrangeUtil.computeCoefficient(Zp.valueOf(i, g.size()),
                    N,
                    Zp.valueOf(baseHash.hashIntoStructure(x).getInteger(), baseHash.getTargetStructure().size())
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
        final int prime = 31;
        int result = 1;
        result = prime * result + ((T == null) ? 0 : T.hashCode());
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
        WatersHash other = (WatersHash) obj;
        if (T == null) {
            if (other.T != null)
                return false;
        } else if (!T.equals(other.T))
            return false;
        return true;
    }

    @Override
    public Element hashIntoStructure(UniqueByteRepresentable ubr) {
        ByteAccumulator acc = new ByteArrayAccumulator();
        acc = ubr.updateAccumulator(acc);
        return hashIntoStructure(acc.extractBytes());
    }
}