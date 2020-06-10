package de.upb.crypto.craco.abe.cp.small;

import de.upb.crypto.craco.interfaces.DecryptionKey;
import de.upb.crypto.craco.interfaces.abe.Attribute;
import de.upb.crypto.craco.interfaces.abe.SetOfAttributes;
import de.upb.crypto.craco.interfaces.pe.KeyIndex;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

import java.util.Map;

/**
 * A {@link DecryptionKey} for the {@link ABECPWat11Small} that stores a
 * {@link SetOfAttributes} as {@link KeyIndex}.
 * <p>
 * This key should be created by
 * {@link ABECPWat11Small#generateDecryptionKey(de.upb.crypto.craco.interfaces.pe.MasterSecret, de.upb.crypto.craco.interfaces.pe.KeyIndex)}
 *
 * @author Mirko Jürgens
 */
public class ABECPWat11SmallDecryptionKey implements DecryptionKey {

    @Represented(restorer = "G1")
    private GroupElement k, l;

    @Represented(restorer = "foo -> G1")
    private Map<Attribute, GroupElement> mapK;

    public ABECPWat11SmallDecryptionKey(Representation repr, ABECPWat11SmallPublicParameters pp) {
        new ReprUtil(this).register(pp.getGroupG1(), "G1").deserialize(repr);
    }

    public ABECPWat11SmallDecryptionKey(Map<Attribute, GroupElement> mapK, GroupElement k, GroupElement l) {
        this.mapK = mapK;
        this.k = k;
        this.l = l;
    }

    public GroupElement getK() {
        return k;
    }

    public GroupElement getL() {
        return l;
    }

    public Map<Attribute, GroupElement> getMapK() {
        return mapK;
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((mapK == null) ? 0 : mapK.hashCode());
        result = prime * result + ((k == null) ? 0 : k.hashCode());
        result = prime * result + ((l == null) ? 0 : l.hashCode());
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
        ABECPWat11SmallDecryptionKey other = (ABECPWat11SmallDecryptionKey) obj;
        if (mapK == null) {
            if (other.mapK != null)
                return false;
        } else if (!mapK.equals(other.mapK))
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
