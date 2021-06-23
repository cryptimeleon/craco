package org.cryptimeleon.craco.protocols.arguments.sigma.schnorr;

import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.hash.UniqueByteRepresentable;
import org.cryptimeleon.math.hash.annotations.AnnotatedUbrUtil;
import org.cryptimeleon.math.hash.annotations.UniqueByteRepresented;
import org.cryptimeleon.math.serialization.ListRepresentation;
import org.cryptimeleon.math.serialization.Representable;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.structures.Element;
import org.cryptimeleon.math.structures.Structure;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.rings.zn.Zn;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * A value that is sent before the rest of the protocol is set up and starts.
 */
public interface SendFirstValue extends Representable, UniqueByteRepresentable {
    /**
     * An empty value to send first
     */
    SendFirstValue EMPTY = new EmptySendFirstValue();

    class EmptySendFirstValue implements SendFirstValue {
        private EmptySendFirstValue() {
        }

        @Override
        public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
            return accumulator;
        }

        @Override
        public Representation getRepresentation() {
            return null;
        }

        @Override
        public int hashCode() {
            return 0;
        }

        @Override
        public boolean equals(Object obj) {
            return obj instanceof EmptySendFirstValue;
        }
    }

    /**
     * A list of algebraic values ({@link Element}s) to send first.
     */
    class AlgebraicSendFirstValue implements SendFirstValue {
        @UniqueByteRepresented
        private final List<Element> elements = new ArrayList<>();

        /**
         * Instantiates the SendFirstValue with an ordered list of values to send.
         */
        public AlgebraicSendFirstValue(Element... values) {
            elements.addAll(Arrays.asList(values));
        }

        /**
         * Recreates the SendFirstValue from representation.
         * @param repr the representation returned by {@link AlgebraicSendFirstValue#getRepresentation()}
         * @param structures the structures to use to restore the sent elements
         *                   (same order as in the {@link AlgebraicSendFirstValue(Element...)} constructor)
         */
        public AlgebraicSendFirstValue(Representation repr, Structure... structures) {
            for (int i=0;i<structures.length;i++)
                elements.add(structures[i].restoreElement(repr.list().get(i)));
        }

        /**
         * Returns the i'th element from the list (zero-based indexing)
         */
        public Element getElement(int i) {
            return elements.get(i);
        }

        /**
         * Returns the i'th element from the list (zero-based indexing)
         */
        public GroupElement getGroupElement(int i) {
            return (GroupElement) getElement(i);
        }

        /**
         * Returns the i'th element from the list (zero-based indexing)
         */
        public Zn.ZnElement getZnElement(int i) {
            return (Zn.ZnElement) getElement(i);
        }

        @Override
        public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
            AnnotatedUbrUtil.autoAccumulate(accumulator,this);
            return accumulator;
        }

        @Override
        public Representation getRepresentation() {
            ListRepresentation repr = new ListRepresentation();
            elements.forEach(elem -> repr.add(elem.getRepresentation()));
            return repr;
        }
    }
}
