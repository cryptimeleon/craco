package de.upb.crypto.craco.kem.abe.cp.os;

import de.upb.crypto.craco.common.interfaces.DecryptionKey;
import de.upb.crypto.craco.abe.interfaces.Attribute;
import de.upb.crypto.craco.abe.interfaces.SetOfAttributes;
import de.upb.crypto.craco.common.interfaces.proxy.TransformationKey;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.MapRepresentation;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;
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

    public GroupElement k0;
    public GroupElement k1;

    public Map<Attribute, GroupElement[]> ki_map;

    public LUDDecryptionKey(GroupElement k0, GroupElement k1, Map<Attribute, GroupElement[]> map) {
        this.k0 = k0;
        this.k1 = k1;
        this.ki_map = map;


    }

    public Set<Attribute> getAttributes() {
        return ki_map.keySet();
    }

    public SetOfAttributes getKeyIndex() {
        return new SetOfAttributes(this.getAttributes());
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation r = new ObjectRepresentation();
        RepresentationUtil.putElement(this, r, "k0");
        RepresentationUtil.putElement(this, r, "k1");
        MapRepresentation mr = RepresentationUtil.representMapOfLists(ki_map);
        r.put("map", mr);
        return r;
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
