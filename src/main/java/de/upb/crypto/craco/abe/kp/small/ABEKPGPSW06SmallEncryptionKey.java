package de.upb.crypto.craco.abe.kp.small;

import de.upb.crypto.craco.interfaces.EncryptionKey;
import de.upb.crypto.craco.interfaces.abe.SetOfAttributes;
import de.upb.crypto.craco.interfaces.pe.CiphertextIndex;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.RepresentableRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

import java.util.Objects;

/**
 * An {@link EncryptionKey} for the {@link ABEKPGPSW06Small} that
 * stores a {@link SetOfAttributes} as {@link CiphertextIndex}.
 * <p>
 * This key should be created by
 * {@link ABEKPGPSW06Small#generateEncryptionKey(CiphertextIndex)}
 *
 * @author Mirko Jürgens
 */
public class ABEKPGPSW06SmallEncryptionKey implements EncryptionKey {
    @UniqueByteRepresented
    @Represented
    private SetOfAttributes attributes;

    public ABEKPGPSW06SmallEncryptionKey(SetOfAttributes attributes) {
        this.attributes = attributes;
    }

    public ABEKPGPSW06SmallEncryptionKey(Representation repr) {
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
        result = prime * result + ((attributes == null) ? 0 : attributes.hashCode());
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
        ABEKPGPSW06SmallEncryptionKey other = (ABEKPGPSW06SmallEncryptionKey) obj;
        return Objects.equals(attributes, other.attributes);
    }

    public SetOfAttributes getAttributes() {
        return attributes;
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }

}
