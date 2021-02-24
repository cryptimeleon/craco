package org.cryptimeleon.craco.protocols.arguments.sigma;

import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.hash.UniqueByteRepresentable;
import org.cryptimeleon.math.serialization.Representable;
import org.cryptimeleon.math.serialization.Representation;

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
}
