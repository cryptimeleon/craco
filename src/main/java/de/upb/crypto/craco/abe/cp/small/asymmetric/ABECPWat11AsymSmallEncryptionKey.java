package de.upb.crypto.craco.abe.cp.small.asymmetric;

import de.upb.crypto.craco.interfaces.EncryptionKey;
import de.upb.crypto.craco.interfaces.policy.Policy;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;

public class ABECPWat11AsymSmallEncryptionKey implements EncryptionKey {

    private Policy policy;

    public ABECPWat11AsymSmallEncryptionKey(Policy policy) {
        this.policy = policy;
    }

    public ABECPWat11AsymSmallEncryptionKey(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    public Policy getPolicy() {
        return policy;
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator byteAccumulator) {
        return AnnotatedUbrUtil.autoAccumulate(byteAccumulator, this);
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
        ABECPWat11AsymSmallEncryptionKey other = (ABECPWat11AsymSmallEncryptionKey) obj;
        if (policy == null) {
            if (other.policy != null)
                return false;
        } else if (!policy.equals(other.policy))
            return false;
        return true;
    }
}
