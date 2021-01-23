package de.upb.crypto.craco.kem.abe.cp.os;

import de.upb.crypto.craco.common.interfaces.EncryptionKey;
import de.upb.crypto.craco.common.interfaces.policy.Policy;
import de.upb.crypto.math.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StandaloneRepresentable;
import de.upb.crypto.math.serialization.annotations.ReprUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.Objects;

/**
 * Class for encryption keys of ElgamalLargeUniverseDelegationKEM.
 * <p>
 * This class is a wrapper around the policy of this encryption key.
 *
 * @author peter.guenther
 */
public class LUDEncryptionKey implements EncryptionKey, StandaloneRepresentable {

    @Represented
    private Policy policy;

    public LUDEncryptionKey(Policy p) {
        this.policy = p;
    }

    public void setPolicy(Policy policy) {
        this.policy = policy;
    }

    public Policy getPolicy() {
        return this.policy;
    }

    public LUDEncryptionKey(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
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
        LUDEncryptionKey other = (LUDEncryptionKey) obj;
        return Objects.equals(policy, other.policy);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return policy.updateAccumulator(accumulator);
    }
}
