package de.upb.crypto.craco.interfaces.abe;

import de.upb.crypto.craco.interfaces.policy.PolicyFact;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StringRepresentation;

import java.util.Collection;

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
