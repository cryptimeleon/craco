package de.upb.crypto.craco.abe.cp.small.asymmetric;

import de.upb.crypto.craco.interfaces.DecryptionKey;
import de.upb.crypto.craco.interfaces.abe.Attribute;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

import java.util.Map;

public class ABECPWat11AsymSmallDecryptionKey implements DecryptionKey {

    @Represented(restorer = "G1")
    private GroupElement k; // K in G_1

    @Represented(restorer = "G2")
    private GroupElement l; // L in G_2

    @Represented(restorer = "foo -> G1")
    private Map<Attribute, GroupElement> mapKx; // K_x in G_1

    public ABECPWat11AsymSmallDecryptionKey(GroupElement k, GroupElement l, Map<Attribute, GroupElement> mapKx) {
        this.k = k;
        this.l = l;
        this.mapKx = mapKx;
    }

    public ABECPWat11AsymSmallDecryptionKey(Representation repr, Group groupG1, Group groupG2) {
        new ReprUtil(this).register(groupG1, "G1").register(groupG2, "G2").deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public GroupElement getK() {
        return k;
    }

    public void setK(GroupElement k) {
        this.k = k;
    }

    public GroupElement getL() {
        return l;
    }

    public void setL(GroupElement l) {
        this.l = l;
    }

    public Map<Attribute, GroupElement> getMapKx() {
        return mapKx;
    }

    public void setMapKx(Map<Attribute, GroupElement> mapKx) {
        this.mapKx = mapKx;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((k == null) ? 0 : k.hashCode());
        result = prime * result + ((l == null) ? 0 : l.hashCode());
        result = prime * result + ((mapKx == null) ? 0 : mapKx.hashCode());
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
        ABECPWat11AsymSmallDecryptionKey other = (ABECPWat11AsymSmallDecryptionKey) obj;
        if (mapKx == null) {
            if (other.mapKx != null)
                return false;
        } else if (!mapKx.equals(other.mapKx))
            return false;
        if (k == null) {
            if (other.k != null)
                return false;
        } else if (!k.equals(other.k))
            return false;
        if (l == null) {
            if (other.l != null)
                return false;
        } else if (!l.equals(other.l))
            return false;
        return true;
    }
}
