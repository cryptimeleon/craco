package de.upb.crypto.craco.common;

import de.upb.crypto.craco.interfaces.PlainText;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.structures.Ring;
import de.upb.crypto.math.interfaces.structures.RingElement;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.RepresentableRepresentation;
import de.upb.crypto.math.serialization.Representation;

import java.util.Objects;

public class RingElementPlainText implements PlainText {
    private RingElement element;

    public RingElementPlainText(RingElement element) {
        this.element = element;
    }

    public RingElementPlainText(Representation repr) {
        Ring ring = (Ring) repr.obj().get("ring").repr().recreateRepresentable();
        this.element = ring.getElement(repr.obj().get("elem"));
    }

    /**
     * Returns the ring element
     *
     * @return this ring element
     */
    public RingElement getRingElement() {
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
        RingElementPlainText other = (RingElementPlainText) obj;
        return Objects.equals(element, other.element);
    }

    @Override
    public String toString() {
        return element.toString();
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return element.updateAccumulator(accumulator);
    }
}
