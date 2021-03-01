package org.cryptimeleon.craco.common.attributes;

import org.cryptimeleon.craco.common.policies.PolicyFact;
import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.hash.annotations.AnnotatedUbrUtil;
import org.cryptimeleon.math.hash.annotations.UniqueByteRepresented;
import org.cryptimeleon.math.serialization.ObjectRepresentation;
import org.cryptimeleon.math.serialization.RepresentableRepresentation;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.structures.rings.Ring;
import org.cryptimeleon.math.structures.rings.RingElement;

import java.util.Collection;

/**
 * An attribute in form of a {@link RingElement}.
 */
public class RingElementAttribute implements Attribute {
    @UniqueByteRepresented
    private RingElement element;

    public RingElementAttribute(RingElement element) {
        this.element = element;
    }

    public RingElementAttribute(Representation repr) {
        Ring ring = (Ring) repr.obj().get("ring").repr().recreateRepresentable();
        this.element = ring.restoreElement(repr.obj().get("elem"));
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
