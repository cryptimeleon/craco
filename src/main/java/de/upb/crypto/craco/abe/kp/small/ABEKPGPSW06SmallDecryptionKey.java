package de.upb.crypto.craco.abe.kp.small;

import de.upb.crypto.craco.common.interfaces.DecryptionKey;
import de.upb.crypto.craco.common.interfaces.pe.KeyIndex;
import de.upb.crypto.craco.common.interfaces.policy.Policy;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

import java.math.BigInteger;
import java.util.Map;
import java.util.Objects;

/**
 * A {@link DecryptionKey} for the {@link ABEKPGPSW06Small} that
 * stores a {@link Policy} as {@link KeyIndex}.
 * <p>
 * This key should be created by
 * {@link ABEKPGPSW06Small#generateDecryptionKey(de.upb.crypto.craco.common.interfaces.pe.MasterSecret, KeyIndex)}
 *
 *
 */
public class ABEKPGPSW06SmallDecryptionKey implements DecryptionKey {

    @Represented
    private Policy policy;
    @Represented(restorer = "int -> G1")
    private Map<BigInteger, GroupElement> D;

    public ABEKPGPSW06SmallDecryptionKey(Policy policy, Map<BigInteger, GroupElement> d) {
        this.policy = policy;
        this.D = d;
    }

    public ABEKPGPSW06SmallDecryptionKey(Representation repr, ABEKPGPSW06SmallPublicParameters kpp) {
        new ReprUtil(this).register(kpp.getGroupG1(), "G1").deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public Policy getPolicy() {
        return policy;
    }

    public Map<BigInteger, GroupElement> getD() {
        return D;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((D == null) ? 0 : D.hashCode());
        result = prime * result + ((policy == null) ? 0 : policy.hashCode());
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
        ABEKPGPSW06SmallDecryptionKey other = (ABEKPGPSW06SmallDecryptionKey) obj;
        return Objects.equals(D, other.D)
                && Objects.equals(policy, other.policy);
    }

}
