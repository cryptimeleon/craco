package de.upb.crypto.craco.interfaces.abe;

import de.upb.crypto.craco.interfaces.policy.PolicyFact;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.structures.Ring;
import de.upb.crypto.math.interfaces.structures.RingElement;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.RepresentableRepresentation;
import de.upb.crypto.math.serialization.Representation;

import java.util.Collection;

public class RingElementAttribute implements Attribute {
    @UniqueByteRepresented
    private RingElement element;

    public RingElementAttribute(RingElement element) {
        this.element = element;
    }

    public RingElementAttribute(Representation repr) {
        Ring ring = (Ring) repr.obj().get("ring").repr().recreateRepresentable();
        this.element = ring.getElement(repr.obj().get("elem"));
    }

    /**
     * Returns the ring element representing the attributes value
     *
     * @return this attributes ring element
     */
    public RingElement getAttribute() {
        return element;
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation result = new ObjectRepresentation();
        result.put("elem", element.getRepresentation());
        result.put("ring", new RepresentableRepresentation(element.getStructure()));
        return result;
    }

    @Override
    public int hashCode() {
        return element.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        RingElementAttribute other = (RingElementAttribute) obj;
        if (element == null) {
            if (other.element != null)
                return false;
        } else if (!element.equals(other.element))
            return false;
        return true;
    }

    @Override
    public String toString() {
        return element.toString();
    }

    @Override
    public boolean isFulfilled(Collection<? extends PolicyFact> facts) {
        return facts.contains(this);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }

}
