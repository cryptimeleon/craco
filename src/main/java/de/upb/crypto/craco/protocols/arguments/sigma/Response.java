package de.upb.crypto.craco.protocols.arguments.sigma;

import de.upb.crypto.math.hash.ByteAccumulator;
import de.upb.crypto.math.hash.UniqueByteRepresentable;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representable;
import de.upb.crypto.math.serialization.Representation;

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
            return new ObjectRepresentation();
        }
    }
}
