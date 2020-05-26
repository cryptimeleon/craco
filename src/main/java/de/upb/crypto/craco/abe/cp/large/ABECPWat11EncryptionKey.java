package de.upb.crypto.craco.abe.cp.large;

import de.upb.crypto.craco.interfaces.EncryptionKey;
import de.upb.crypto.craco.interfaces.pe.CiphertextIndex;
import de.upb.crypto.craco.interfaces.policy.Policy;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

/**
 * An {@link EncryptionKey} for the {@link ABECPWat11} that stores a
 * {@link Policy} as {@link CiphertextIndex}.
 * <p>
 * This key should be created by
 * {@link ABECPWat11#generateEncryptionKey(de.upb.crypto.craco.interfaces.pe.CiphertextIndex)}
 *
 * @author Mirko Jürgens, Jan
 */
public class ABECPWat11EncryptionKey implements EncryptionKey {

    @UniqueByteRepresented
    @Represented
    private Policy policy;

    public ABECPWat11EncryptionKey(Policy policy) {
        this.policy = policy;
    }

    public ABECPWat11EncryptionKey(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    public Policy getPolicy() {
        return policy;
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
        ABECPWat11EncryptionKey other = (ABECPWat11EncryptionKey) obj;
        if (policy == null) {
            if (other.policy != null)
                return false;
        } else if (!policy.equals(other.policy))
            return false;
        return true;
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }

}
