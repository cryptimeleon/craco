package org.cryptimeleon.craco.common.attributes;

import org.cryptimeleon.craco.common.policies.PolicyFact;
import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.StringRepresentation;

import java.util.Collection;

/**
 * An attribute in form of a {@link String}.
 */
public class StringAttribute implements Attribute {
    private String attribute;

    public StringAttribute(String name) {
        this.attribute = name;
    }

    public StringAttribute(Representation repr) {
        this.attribute = repr.str().get();
    }

    public String getAttributeName() {
        return attribute;
    }

    @Override
    public Representation getRepresentation() {
        return new StringRepresentation(attribute);
    }

    @Override
    public int hashCode() {
        return attribute.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        StringAttribute other = (StringAttribute) obj;
        if (attribute == null) {
            if (other.attribute != null)
                return false;
        } else if (!attribute.equals(other.attribute))
            return false;
        return true;
    }

    @Override
    public String toString() {
        return attribute;
    }

    @Override
    public boolean isFulfilled(Collection<? extends PolicyFact> facts) {
        return facts.contains(this);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        accumulator.escapeAndAppend(attribute);
        return accumulator;
    }
}
