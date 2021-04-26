package org.cryptimeleon.craco.protocols.arguments.sigma;

import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.hash.UniqueByteRepresentable;
import org.cryptimeleon.math.serialization.ListRepresentation;
import org.cryptimeleon.math.serialization.Representable;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.structures.cartesian.Vector;

import java.util.List;

/**
 * A {@link SigmaProtocol}'s third message.
 */
public interface Response extends Representable, UniqueByteRepresentable {
    static EmptyResponse EMPTY = new EmptyResponse();
    class EmptyResponse implements Response {
        private EmptyResponse() {

        }

        @Override
        public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
            return accumulator;
        }

        @Override
        public Representation getRepresentation() {
            return null;
        }
    }

    public class ResponseVector extends Vector<Response> implements Response {

        public ResponseVector(Response... responses) {
            super(responses);
        }

        public ResponseVector(List<? extends Response> responses) {
            super(responses);
        }

        @Override
        public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
            forEach(accumulator::escapeAndSeparate);
            return accumulator;
        }

        @Override
        public Representation getRepresentation() {
            return new ListRepresentation(map(Representable::getRepresentation));
        }
    }
}
