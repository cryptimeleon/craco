package de.upb.crypto.craco.kem.abe.cp.os;

import de.upb.crypto.craco.interfaces.DecryptionKey;
import de.upb.crypto.craco.interfaces.abe.Attribute;
import de.upb.crypto.craco.interfaces.abe.SetOfAttributes;
import de.upb.crypto.craco.interfaces.proxy.TransformationKey;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.MapRepresentation;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;
import de.upb.crypto.math.serialization.util.RepresentationUtil;

import java.util.Arrays;
import java.util.Map;
import java.util.Set;

/**
 * Decryption and transformation key for ElgamalLargeUniverseDelegationKEM.
 * <p>
 * Decryption keys and transformation keys have exactly the same structure, hence both can be represented with one
 * class.
 * <p>
 * * K0= g1^alpha w1^r
 * K1= g1^r
 * <p>
 * For attributes ai:
 * K_ai,2 = g1^r_ai
 * K_ai,3 = (u1^H(ai) h1)^r_ai v^-r
 *
 * @author peter.guenther
 */
public class LUDDecryptionKey implements DecryptionKey, TransformationKey {

    @Represented(restorer = "G1")
    public GroupElement k0;

    @Represented(restorer = "G1")
    public GroupElement k1;

    @Represented(restorer = "attr -> [G1]")
    public Map<Attribute, GroupElement[]> ki_map;

    public LUDDecryptionKey(GroupElement k0, GroupElement k1, Map<Attribute, GroupElement[]> map) {
        this.k0 = k0;
        this.k1 = k1;
        this.ki_map = map;
    }

    public LUDDecryptionKey(Representation repr, Group groupG1) {
        new ReprUtil(this).register(groupG1, "G1").deserialize(repr);
    }

    public Set<Attribute> getAttributes() {
        return ki_map.keySet();
    }

    public SetOfAttributes getKeyIndex() {
        return new SetOfAttributes(this.getAttributes());
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public GroupElement getK0() {
        return k0;
    }

    public void setK0(GroupElement k0) {
        this.k0 = k0;
    }

    public GroupElement getK1() {
        return k1;
    }

    public void setK1(GroupElement k1) {
        this.k1 = k1;
    }

    public Map<Attribute, GroupElement[]> getKi_map() {
        return ki_map;
    }

    public void setKi_map(Map<Attribute, GroupElement[]> ki_map) {
        this.ki_map = ki_map;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((k0 == null) ? 0 : k0.hashCode());
        result = prime * result + ((k1 == null) ? 0 : k1.hashCode());
        result = prime * result + ((ki_map == null) ? 0 : ki_map.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (!(obj instanceof LUDDecryptionKey))
            return false;
        LUDDecryptionKey other = (LUDDecryptionKey) obj;
        if (k0 == null) {
            if (other.k0 != null)
                return false;
        } else if (!k0.equals(other.k0))
            return false;
        if (k1 == null) {
            if (other.k1 != null)
                return false;
        } else if (!k1.equals(other.k1))
            return false;
        if (ki_map == null) {
            if (other.ki_map != null)
                return false;
        } else {
            if (ki_map.size() != other.ki_map.size()) {
                return false;
            }
            /*
             * non-generic comparison of  Maps. Here, generic test fails becaus second argument is native array.
             */
            for (Map.Entry<Attribute, GroupElement[]> entry : ki_map.entrySet()) {
                if (!other.ki_map.containsKey(entry.getKey()))
                    return false;
                if (!Arrays.equals(entry.getValue(), other.ki_map.get(entry.getKey())))
                    return false;
            }
        }

        return true;
    }

}
