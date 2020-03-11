package de.upb.crypto.craco.abe.cp.small;

import de.upb.crypto.craco.interfaces.DecryptionKey;
import de.upb.crypto.craco.interfaces.abe.Attribute;
import de.upb.crypto.craco.interfaces.abe.SetOfAttributes;
import de.upb.crypto.craco.interfaces.pe.KeyIndex;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
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
    private GroupElement d_prime, d_prime2;

    @Represented(restorer = "foo -> G1")
    private Map<Attribute, GroupElement> d;

    @SuppressWarnings("unused")
    private Group groupG1;

    public ABECPWat11SmallDecryptionKey(Representation repr, ABECPWat11SmallPublicParameters pp) {
        groupG1 = pp.getGroupG1();
        new ReprUtil(this).register(groupG1, "G1").deserialize(repr);
    }

    public ABECPWat11SmallDecryptionKey(Map<Attribute, GroupElement> d, GroupElement d_prime, GroupElement d_prime2) {
        this.d = d;
        this.d_prime = d_prime;
        this.d_prime2 = d_prime2;
    }

    public GroupElement getD_prime() {
        return d_prime;
    }

    public GroupElement getD_prime2() {
        return d_prime2;
    }

    public Map<Attribute, GroupElement> getD() {
        return d;
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((d == null) ? 0 : d.hashCode());
        result = prime * result + ((d_prime == null) ? 0 : d_prime.hashCode());
        result = prime * result + ((d_prime2 == null) ? 0 : d_prime2.hashCode());
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
        if (d == null) {
            if (other.d != null)
                return false;
        } else if (!d.equals(other.d))
            return false;
        if (d_prime == null) {
            if (other.d_prime != null)
                return false;
        } else if (!d_prime.equals(other.d_prime))
            return false;
        if (d_prime2 == null) {
            if (other.d_prime2 != null)
                return false;
        } else if (!d_prime2.equals(other.d_prime2))
            return false;
        return true;
    }

}
