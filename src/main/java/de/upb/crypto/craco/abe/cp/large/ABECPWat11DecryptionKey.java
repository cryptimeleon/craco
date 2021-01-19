package de.upb.crypto.craco.abe.cp.large;

import de.upb.crypto.craco.abe.interfaces.Attribute;
import de.upb.crypto.craco.abe.interfaces.SetOfAttributes;
import de.upb.crypto.craco.common.interfaces.DecryptionKey;
import de.upb.crypto.craco.common.interfaces.pe.KeyIndex;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

import java.util.Map;
import java.util.Objects;

/**
 * A {@link DecryptionKey} for the {@link ABECPWat11} that stores
 * a {@link SetOfAttributes} as {@link KeyIndex}.
 * <p>
 * This key should be created by
 * {@link ABECPWat11#generateDecryptionKey(de.upb.crypto.craco.common.interfaces.pe.MasterSecret, de.upb.crypto.craco.common.interfaces.pe.KeyIndex)}
 */
public class ABECPWat11DecryptionKey implements DecryptionKey {

    @Represented(restorer = "G1")
    private GroupElement d_prime, d_prime2;

    @Represented(restorer = "attr -> G1")
    private Map<Attribute, GroupElement> d;

    public ABECPWat11DecryptionKey(Representation repr, ABECPWat11PublicParameters pp) {
        new ReprUtil(this).register(pp.getGroupG1(), "G1").deserialize(repr);
    }

    public ABECPWat11DecryptionKey(Map<Attribute, GroupElement> d, GroupElement d_prime, GroupElement d_prime2) {
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
        ABECPWat11DecryptionKey other = (ABECPWat11DecryptionKey) obj;
        return Objects.equals(d, other.d)
                && Objects.equals(d_prime, other.d_prime)
                && Objects.equals(d_prime2, other.d_prime2);
    }
}
