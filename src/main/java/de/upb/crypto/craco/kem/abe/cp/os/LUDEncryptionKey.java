package de.upb.crypto.craco.kem.abe.cp.os;

import de.upb.crypto.craco.interfaces.EncryptionKey;
import de.upb.crypto.craco.interfaces.policy.Policy;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.RepresentableRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StandaloneRepresentable;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

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
        //this.policy = (Policy) ((RepresentableRepresentation) repr).recreateRepresentable();
        new ReprUtil(this).deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
        //return new RepresentableRepresentation(policy);
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
        if (!(obj instanceof LUDEncryptionKey))
            return false;
        LUDEncryptionKey other = (LUDEncryptionKey) obj;
        if (policy == null) {
            if (other.policy != null)
                return false;
        } else if (!policy.equals(other.policy))
            return false;
        return true;
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return policy.updateAccumulator(accumulator);
    }


}
